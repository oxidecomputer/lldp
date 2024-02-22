use std::ffi::{CStr, CString};
use std::fmt;
use std::sync::Mutex;

mod ffi;

pub type PcapResult<T> = Result<T, PcapError>;

#[derive(Debug, thiserror::Error)]
pub enum PcapError {
    /// The daemon attempted to perform a task the required contacting dpd without
    /// being connected to a dpd instance.
    #[error("Not connected to dpd daemon")]
    NoDpd,
    #[error("libpcap error: {0}")]
    Library(String),
    #[error("unix error during poll: {0}")]
    Poll(i32),
    #[error("handle already activated")]
    Activated,
    #[error("handle not yet activated")]
    NotActivated,
    #[error("handle closed")]
    Closed,
}

pub enum HandleType {
    File,
    Interface,
}

pub struct Pcap {
    htype: HandleType,
    name: String,
    activated: bool,
    lib_hdl: *mut ffi::pcap,
    raw_fd: std::os::raw::c_int,
    lock: Mutex<()>,
}
unsafe impl Send for Pcap {}
unsafe impl Sync for Pcap {}

impl Drop for Pcap {
    fn drop(&mut self) {
        self.close();
    }
}

impl fmt::Debug for Pcap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}",
            match self.htype {
                HandleType::Interface => "interface",
                HandleType::File => "file",
            },
            self.name
        )
    }
}

const PCAP_ERRBUF_SIZE: usize = 256;
const EMPTY_DATA: [u8; 0] = [];

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

        unsafe { ffi::pcap_activate(self.lib_hdl).error_check(self.lib_hdl)? };
        self.activated = true;

        unsafe {
            let mut err = [0i8; PCAP_ERRBUF_SIZE];
            let fd = ffi::pcap_get_selectable_fd(self.lib_hdl);
            if fd >= 0 {
                self.raw_fd = fd;
            }
        }

        Ok(())
    }

    pub fn close(&self) {
        let _lock = self.lock.lock();
        if self.activated {
            /*
            if self.raw_fd >= 0 {
                let _ = nix::unistd::close(self.raw_fd);
            }
            */
            unsafe { ffi::pcap_close(self.lib_hdl) };
        }
    }

    pub fn breakloop(&self) {
        unsafe { ffi::pcap_breakloop(self.lib_hdl) };
    }

    // Built on top of pcap's "get next packet" call, this routine will block
    // until a packet arrives and will invoke the provided callback to process
    // it.
    pub fn dispatch<T: Copy>(
        &self,
        cnt: u32,
        callback: fn(&Pcap, &[u8], T),
        cookie: T,
    ) -> PcapResult<()> {
        let mut packets = 0;
        loop {
            let mut hdr: *mut ffi::pcap_pkthdr = std::ptr::null_mut();
            let mut data: *const u8 = std::ptr::null_mut();

            let _lock = self.lock.lock();
            if !self.activated {
                break;
            }
            match unsafe {
                ffi::pcap_next_ex(self.lib_hdl, &mut hdr, &mut data)
            } {
                -2 => break, // -2 means a clean shutdown
                x => x.error_check(self.lib_hdl)?,
            };

            let packet;
            unsafe {
                let pkt_len = (*hdr).caplen as usize;
                packet = std::slice::from_raw_parts(data, pkt_len);
            }
            callback(self, packet, cookie);

            packets += 1;
            if cnt > 0 && packets >= cnt {
                break;
            }
        }
        Ok(())
    }

    fn fetch(&self) -> PcapResult<Option<&[u8]>> {
        let mut hdr: *mut ffi::pcap_pkthdr = std::ptr::null_mut();
        let mut data: *const u8 = std::ptr::null_mut();

        let _lock = self.lock.lock();
        unsafe {
            match ffi::pcap_next_ex(self.lib_hdl, &mut hdr, &mut data) {
                -2 => Ok(None),
                -1 => Err(get_hdl_error(self.lib_hdl)),
                0 => Ok(Some(&EMPTY_DATA)),
                1 => {
                    let pkt_len = (*hdr).caplen as usize;
                    let s = std::slice::from_raw_parts(data, pkt_len);
                    Ok(Some(s))
                }
                x => Err(PcapError::Library(format!(
                    "unexpected rval from pcap: {x}"
                ))),
            }
        }
    }

    // Block until a packet arrives
    pub fn next(&self) -> PcapResult<Option<&[u8]>> {
        // This loop is here because libpcap's timeout and breakloop mechanisms
        // don't seem all that reliable, and because closing the pcap handle
        // and/or file descriptor doesn't interrupt a blocked process.
        // Note: even this isn't sufficient to get a timely, clean shutdown on
        // all systems since even pcap_setnonblock() also doesn't seem reliable
        // everywhere.  Sigh.
        loop {
            match self.fetch() {
                Err(e) => return Err(e),
                Ok(None) => return Ok(None),
                Ok(Some(data)) => {
                    if !data.is_empty() {
                        return Ok(Some(data));
                    }
                }
            }
        }
    }

    pub fn next_owned(&self) -> PcapResult<Option<Vec<u8>>> {
        self.next().map(|d| d.map(|v| v.to_vec()))
    }

    // Send a single packet
    pub fn send(&self, packet: &[u8]) -> PcapResult<i32> {
        let _lock = self.lock.lock();
        if !self.activated {
            Err(PcapError::NotActivated)
        } else {
            unsafe {
                let ptr = packet.as_ptr() as *const core::ffi::c_void;
                let len = packet.len();
                ffi::pcap_inject(self.lib_hdl, ptr, len)
                    .error_check(self.lib_hdl)
            }
        }
    }

    // Prior to activating the pcap handle, set the read timeout
    pub fn set_timeout(&self, ms: i32) -> PcapResult<()> {
        let _lock = self.lock.lock();
        unsafe { ffi::pcap_set_timeout(self.lib_hdl, ms) }
            .error_check(self.lib_hdl)?;
        Ok(())
    }

    // Pass a compiled BPF program to pcap to impose a filter on the packets
    // returned.
    pub fn set_filter(&self, fp: &mut ffi::bpf_program) -> PcapResult<()> {
        unsafe { ffi::pcap_setfilter(self.lib_hdl, fp) }
            .error_check(self.lib_hdl)?;
        Ok(())
    }

    // Compile a BPF filter/program from text to BPF code
    pub fn compile(
        &self,
        program: &str,
        netmask: u32,
    ) -> PcapResult<ffi::bpf_program> {
        let mut bpf = ffi::bpf_program {
            bf_len: 0,
            bf_insns: std::ptr::null_mut(),
        };

        unsafe {
            let arg = CString::new(program).expect("CString::new failed");
            ffi::pcap_compile(self.lib_hdl, &mut bpf, arg.as_ptr(), 0, netmask)
        }
        .error_check(self.lib_hdl)
        .map(|_| bpf)
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
                htype: HandleType::Interface,
                name: iface_name.to_string(),
                activated: false,
                lib_hdl,
                raw_fd: -1,
                lock: Mutex::new(()),
            })
        }
    }
}

// Open a file as a pcap source, and return an opaque handle to the caller.
pub fn open_offline(name: &str) -> PcapResult<Pcap> {
    let filename = CString::new(name).unwrap();
    let mut errbuf = [0i8; PCAP_ERRBUF_SIZE];

    unsafe {
        let cap =
            ffi::pcap_open_offline(filename.as_ptr(), errbuf.as_mut_ptr());
        if cap.is_null() {
            Err(get_library_error(&errbuf as *const i8))
        } else {
            Ok(Pcap {
                htype: HandleType::File,
                name: name.to_string(),
                activated: false,
                lib_hdl: cap,
                raw_fd: -1,
                lock: Mutex::new(()),
            })
        }
    }
}

pub fn null() -> Pcap {
    Pcap {
        htype: HandleType::File,
        name: String::new(),
        activated: false,
        lib_hdl: std::ptr::null_mut(),
        raw_fd: -1,
        lock: Mutex::new(()),
    }
}
