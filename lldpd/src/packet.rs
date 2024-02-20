use common::MacAddr;

use crate::types::LldpdError;
use crate::types::LldpdResult;

pub const ETHER_VLAN: u16 = 0x8100;
pub const ETHER_LLDP: u16 = 0x88cc;
pub const ETHER_LEN: u16 = 14;

#[derive(Clone, Debug)]
pub struct Packet {
    pub eth_hdr: EthHdr,
    pub lldp_hdr: LldpHdr,
}

impl Packet {
    pub fn new(eth_dmac: MacAddr, eth_smac: MacAddr) -> Packet {
        Packet {
            eth_hdr: EthHdr {
                eth_dmac,
                eth_smac,
                eth_8021q: None,
                eth_type: ETHER_LLDP,
                eth_size: ETHER_LEN,
            },
            lldp_hdr: LldpHdr {
                lldp_data: Vec::new(),
            },
        }
    }

    pub fn parse(data: &[u8]) -> LldpdResult<Option<Packet>> {
        let (mut eth_hdr, bytes) = EthHdr::parse(data)?;
        if eth_hdr.eth_type != ETHER_LLDP {
            Ok(None)
        } else {
            let (lldp_hdr, bytes) = LldpHdr::parse(&data[bytes..])?;
            eth_hdr.eth_size += bytes as u16;
            Ok(Some(Packet { eth_hdr, lldp_hdr }))
        }
    }

    pub fn deparse(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.eth_hdr.eth_size as usize);
        self.eth_hdr.deparse(&mut bytes);
        self.lldp_hdr.deparse(&mut bytes);
        bytes
    }

    pub fn add_tlv(&mut self, tlv: &LldpTlv) {
        self.lldp_hdr.add_tlv(tlv)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct EthQHdr {
    pub eth_pcp: u8,       // 802.1q Priority code point
    pub eth_dei: u8,       // 802.1q Drop eligible indicator
    pub eth_vlan_tag: u16, // 802.1q VID
}

impl From<EthQHdr> for u16 {
    fn from(x: EthQHdr) -> Self {
        ((x.eth_pcp as u16) << 13) | ((x.eth_dei as u16) << 12) | x.eth_vlan_tag
    }
}

impl From<u16> for EthQHdr {
    fn from(x: u16) -> Self {
        EthQHdr {
            eth_pcp: ((x >> 13) & 0x07) as u8,
            eth_dei: ((x >> 12) & 0x01) as u8,
            eth_vlan_tag: x & 0xfff,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct EthHdr {
    pub eth_dmac: MacAddr,
    pub eth_smac: MacAddr,
    pub eth_8021q: Option<EthQHdr>,
    pub eth_type: u16,
    pub eth_size: u16,
}

impl EthHdr {
    pub fn parse(data: &[u8]) -> LldpdResult<(EthHdr, usize)> {
        if data.len() < ETHER_LEN as usize {
            return Err(parse_error("ethernet header too short"));
        }
        let mut eth_hdr = EthHdr {
            eth_dmac: MacAddr::from_slice(&data[0..6]),
            eth_smac: MacAddr::from_slice(&data[6..12]),
            eth_8021q: None,
            eth_type: get_u16(&data[12..])?,
            eth_size: ETHER_LEN,
        };

        if eth_hdr.eth_type == ETHER_VLAN {
            eth_hdr.eth_size = 4;
            if data.len() < eth_hdr.eth_size as usize {
                return Err(parse_error("vlan header too short"));
            }
            let word = get_u16(&data[14..])?;
            let eth_8021q = word.into();
            eth_hdr.eth_8021q = Some(eth_8021q);
            eth_hdr.eth_type = get_u16(&data[16..])?;
        }
        Ok((eth_hdr, eth_hdr.eth_size as usize))
    }

    pub fn deparse(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.eth_dmac.to_vec());
        bytes.extend_from_slice(&self.eth_smac.to_vec());
        if let Some(q) = self.eth_8021q {
            bytes.extend_from_slice(&get_bytes(ETHER_VLAN));
            bytes.extend_from_slice(&get_bytes(q.into()));
        }
        bytes.extend_from_slice(&get_bytes(self.eth_type));
    }
}

#[derive(Clone, Debug)]
pub struct LldpHdr {
    pub lldp_data: Vec<LldpTlv>,
}

impl LldpHdr {
    fn parse(data: &[u8]) -> LldpdResult<(LldpHdr, usize)> {
        let mut lldp_data = Vec::new();
        let mut offset = 0;
        let mut done = false;
        while !done {
            if offset >= data.len() {
                return Err(parse_error("packet too short"));
            }
            let (tlv, bytes) = LldpTlv::parse(&data[offset..])?;
            done = tlv.lldp_tlv_type == 0;
            offset += bytes;
            lldp_data.push(tlv);
        }
        Ok((LldpHdr { lldp_data }, offset))
    }

    pub fn deparse(&self, bytes: &mut Vec<u8>) {
        for tlv in &self.lldp_data {
            tlv.deparse(bytes);
        }
    }

    pub fn add_tlv(&mut self, tlv: &LldpTlv) {
        self.lldp_data.push(tlv.clone());
    }
}

#[derive(Clone, Debug)]
pub struct LldpTlv {
    pub lldp_tlv_type: u8,  // 7 bits
    pub lldp_tlv_size: u16, // 9 bits
    pub lldp_tlv_octets: Vec<u8>,
}

impl LldpTlv {
    pub fn new(tlv_type: u8, tlv_data: &[u8]) -> LldpdResult<Self> {
        let tlv_size = tlv_data.len();
        if tlv_type & 0x80 != 0 {
            Err(invalid_error("Invalid tlv_type"))
        } else if tlv_size > 511 {
            Err(invalid_error("tlv_data exceeds 511 octets"))
        } else {
            Ok(LldpTlv {
                lldp_tlv_type: tlv_type,
                lldp_tlv_size: tlv_size as u16,
                lldp_tlv_octets: tlv_data.into(),
            })
        }
    }

    fn parse(data: &[u8]) -> LldpdResult<(LldpTlv, usize)> {
        if data.len() < 2 {
            return Err(parse_error("lldp tlv prefix too short"));
        }

        let word = get_u16(data)?;
        let lldp_tlv_type = (word >> 9) as u8;
        let lldp_tlv_size = word & 0x1ff;
        let end = 2 + lldp_tlv_size as usize;

        if end > data.len() {
            return Err(parse_error("lldp tlv too short"));
        }
        Ok((
            LldpTlv {
                lldp_tlv_type,
                lldp_tlv_size,
                lldp_tlv_octets: data[2..end].to_vec(),
            },
            end,
        ))
    }
    fn deparse(&self, bytes: &mut Vec<u8>) {
        let w = (self.lldp_tlv_type as u16) << 9 | self.lldp_tlv_size;
        bytes.extend_from_slice(&get_bytes(w));
        bytes.extend_from_slice(&self.lldp_tlv_octets);
    }
}

fn get_u16(data: &[u8]) -> LldpdResult<u16> {
    if data.len() < 2 {
        Err(parse_error("buffer too small"))
    } else {
        Ok((data[0] as u16) << 8 | data[1] as u16)
    }
}

fn get_bytes(data: u16) -> [u8; 2] {
    [(data >> 8 & 0xff) as u8, (data & 0xff) as u8]
}

/// Utility function to generate an Invalid error
pub fn invalid_error(message: impl ToString) -> LldpdError {
    LldpdError::Invalid(message.to_string())
}

/// Utility function to generate a Parse error
pub fn parse_error(message: impl ToString) -> LldpdError {
    LldpdError::Protocol(message.to_string())
}
