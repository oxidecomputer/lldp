use crate::types::LldpdError;
use crate::types::LldpdResult;
use crate::Global;
use common::MacAddr;

pub struct Transport {
    pcap_in: pcap::Pcap,
    pcap_out: pcap::Pcap,
}

fn pcap_open(iface: &str) -> LldpdResult<pcap::Pcap> {
    let mut pcap = pcap::create(&Some(iface))
        .map_err(|e| LldpdError::Pcap(format!("failed to open pcap: {e:?}")))?;
    pcap.set_timeout(1)
        .expect("setting the pcap timeout to this constant should never fail");
    if let Err(e) = pcap.activate() {
        pcap.close();
        Err(LldpdError::Pcap(format!("failed to activate pcap: {e:?}")))
    } else {
        Ok(pcap)
    }
}

impl Transport {
    pub fn new(iface: &str) -> LldpdResult<Transport> {
        let pcap_in = pcap_open(iface).map_err(|e| {
            LldpdError::Pcap(format!("failed to open inbound pcap: {e:?}"))
        })?;
        pcap_open(iface)
            .map_err(|e| {
                pcap_in.close();
                LldpdError::Pcap(format!("failed to open inbound pcap: {e:?}"))
            })
            .map(|pcap_out| Transport { pcap_in, pcap_out })
    }

    pub fn get_poll_fd(&self) -> i32 {
        self.pcap_in.raw_fd()
    }

    pub fn packet_send(&self, data: &[u8]) -> LldpdResult<i32> {
        self.pcap_out
            .send(data)
            .map_err(|e| LldpdError::Pcap(e.to_string()))
    }

    pub fn packet_recv(&self) -> LldpdResult<Option<&[u8]>> {
        self.pcap_in
            .next()
            .map_err(|e| LldpdError::Pcap(e.to_string()))
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
