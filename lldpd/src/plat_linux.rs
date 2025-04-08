// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Copyright 2024 Oxide Computer Company

use crate::Global;
use crate::LldpdError;
use crate::LldpdResult;
use protocol::macaddr::MacAddr;
use tokio::io::unix::AsyncFd;

mod pcap {
    use crate::ffi;
    use std::ffi::{CStr, CString};
    use std::sync::Mutex;

    const PCAP_ERRBUF_SIZE: usize = 256;

    pub type PcapResult<T> = Result<T, PcapError>;

    #[derive(Debug, thiserror::Error)]
    pub enum PcapError {
        #[error("libpcap error: {0}")]
        Library(String),
        #[error("handle already activated")]
        Activated,
        #[error("handle not yet activated")]
        NotActivated,
        #[error("buffer too small for incoming packet. have: {0}  need: {1}")]
        TooSmall(usize, usize),
    }

    pub struct Pcap {
        activated: bool,
        lib_hdl: *mut ffi::pcap,
        raw_fd: std::os::raw::c_int,
        lock: Mutex<()>,
    }
    unsafe impl Send for Pcap {}
    unsafe impl Sync for Pcap {}

    impl Drop for Pcap {
        fn drop(&mut self) {
            if self.activated {
                unsafe { ffi::pcap_close(self.lib_hdl) };
            }
        }
    }

    trait PcapErrorCheck {
        fn error_check(&self, hdl: *mut ffi::pcap) -> PcapResult<i32>;
    }

    impl PcapErrorCheck for i32 {
        fn error_check(&self, hdl: *mut ffi::pcap) -> PcapResult<i32> {
            // According to the man page, -1 is returned for all errors.
            // This turns out not be the case.
            if *self < 0 {
                Err(get_hdl_error(hdl))
            } else {
                Ok(*self)
            }
        }
    }

    fn get_error_str(ptr: *const i8) -> String {
        unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() }
    }

    fn get_library_error(ptr: *const i8) -> PcapError {
        PcapError::Library(get_error_str(ptr))
    }

    fn get_hdl_error_str(hdl: *mut ffi::pcap) -> String {
        unsafe { get_error_str(ffi::pcap_geterr(hdl)) }
    }

    fn get_hdl_error(hdl: *mut ffi::pcap) -> PcapError {
        PcapError::Library(get_hdl_error_str(hdl))
    }

    impl Pcap {
        pub fn activate(&mut self) -> PcapResult<()> {
            let _lock = self.lock.lock();

            if self.activated {
                return Err(PcapError::Activated);
            }

            unsafe {
                let mut err = [0i8; PCAP_ERRBUF_SIZE];
                ffi::pcap_set_timeout(self.lib_hdl, 10)
                    .error_check(self.lib_hdl)?;
                ffi::pcap_activate(self.lib_hdl).error_check(self.lib_hdl)?;
                let fd = ffi::pcap_get_selectable_fd(self.lib_hdl);
                if fd >= 0 {
                    self.raw_fd = fd;
                }
            }
            self.activated = true;

            Ok(())
        }

        pub fn fetch(&self, buf: &mut [u8]) -> PcapResult<Option<usize>> {
            let mut hdr: *mut ffi::pcap_pkthdr = std::ptr::null_mut();
            let mut data: *const u8 = std::ptr::null_mut();

            let _lock = self.lock.lock();
            unsafe {
                match ffi::pcap_next_ex(self.lib_hdl, &mut hdr, &mut data) {
                    -2 => Ok(None),
                    -1 => Err(get_hdl_error(self.lib_hdl)),
                    0 => Ok(Some(0)),
                    1 => {
                        let pkt_len = (*hdr).caplen as usize;
                        if pkt_len > buf.len() {
                            Err(PcapError::TooSmall(buf.len(), pkt_len))
                        } else {
                            std::ptr::copy_nonoverlapping(
                                data,
                                buf.as_mut_ptr(),
                                pkt_len,
                            );
                            Ok(Some(pkt_len))
                        }
                    }
                    x => Err(PcapError::Library(format!(
                        "unexpected rval from pcap: {x}"
                    ))),
                }
            }
        }

        // Send a single packet
        pub fn send(&self, packet: &[u8]) -> PcapResult<i32> {
            let _lock = self.lock.lock();
            if !self.activated {
                Err(PcapError::NotActivated)
            } else {
                unsafe {
                    let ptr = packet.as_ptr() as *const core::ffi::c_void;
                    ffi::pcap_inject(self.lib_hdl, ptr, packet.len())
                        .error_check(self.lib_hdl)
                }
            }
        }

        pub fn raw_fd(&self) -> i32 {
            self.raw_fd
        }
    }

    /// Open a network interface for pcap access and return an opaque handle to the
    /// caller, which will be used for all subsequent operations on the interface.
    ///
    /// If the interface name is `None`, then the return `Pcap` will capture packets
    /// from all interfaces.
    pub fn create(iface: &Option<&str>) -> PcapResult<Pcap> {
        // If we're provided an interface name, use it. Otherwise use `"any"` to
        // indicate we want to intercept packets from all interfaces.
        let iface_name = iface.unwrap_or_else(|| "any");
        let s = CString::new(iface_name).unwrap();
        let mut errbuf = [0i8; PCAP_ERRBUF_SIZE];

        unsafe {
            let lib_hdl = ffi::pcap_create(s.as_ptr(), errbuf.as_mut_ptr());
            if lib_hdl.is_null() {
                Err(get_library_error(&errbuf as *const i8))
            } else {
                Ok(Pcap {
                    activated: false,
                    lib_hdl,
                    raw_fd: -1,
                    lock: Mutex::new(()),
                })
            }
        }
    }
}

pub struct Transport {
    pcap_in: pcap::Pcap,
    pcap_out: pcap::Pcap,
    asyncfd: AsyncFd<i32>,
}

fn pcap_open(iface: &str) -> LldpdResult<pcap::Pcap> {
    pcap::create(&Some(iface))
        .map_err(|e| LldpdError::Pcap(format!("failed to open pcap: {e:?}")))
        .and_then(|mut pcap| {
            pcap.activate()
                .map_err(|e| {
                    LldpdError::Pcap(format!("failed to activate pcap: {e:?}"))
                })
                .map(|_| pcap)
        })
}

impl Transport {
    pub fn new(iface: &str) -> LldpdResult<Transport> {
        let pcap_in = pcap_open(iface).map_err(|e| {
            LldpdError::Pcap(format!("failed to open inbound pcap: {e:?}"))
        })?;
        let in_fd = pcap_in.raw_fd();
        let asyncfd = AsyncFd::new(in_fd)
            .map_err(|e| LldpdError::Other(e.to_string()))?;
        pcap_open(iface)
            .map_err(|e| {
                LldpdError::Pcap(format!("failed to open inbound pcap: {e:?}"))
            })
            .map(|pcap_out| Transport {
                pcap_in,
                pcap_out,
                asyncfd,
            })
    }

    pub async fn readable(&self) -> LldpdResult<()> {
        self.asyncfd
            .readable()
            .await
            .map(|_| ())
            .map_err(|e| e.into())
    }

    pub fn packet_send(&self, data: &[u8]) -> LldpdResult<()> {
        self.pcap_out
            .send(data)
            .map_err(|e| LldpdError::Pcap(e.to_string()))
            .map(|_| ())
    }

    pub fn packet_recv(&self, buf: &mut [u8]) -> LldpdResult<Option<usize>> {
        self.pcap_in.fetch(buf).map_err(|e| match e {
            pcap::PcapError::TooSmall(a, b) => LldpdError::TooSmall(a, b),
            other => LldpdError::Pcap(other.to_string()),
        })
    }
}

pub async fn get_iface_and_mac(
    _g: &Global,
    name: &str,
) -> LldpdResult<(String, MacAddr)> {
    let addr_file = format!("/sys/class/net/{name}/address");
    let mac = std::fs::read_to_string(addr_file)?;
    Ok((
        name.to_string(),
        mac.trim().parse().map_err(|e| {
            LldpdError::Other(format!(
                "failed to parse mac address {mac}: {e:?}"
            ))
        })?,
    ))
}
