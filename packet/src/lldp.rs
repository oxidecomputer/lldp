use std::convert::Into;
use std::fmt::{self};

use bytes::BufMut;
use bytes::BytesMut;

use crate::Endpoint;
use crate::Headers;
use crate::Packet;
use crate::PacketResult;
use crate::Protocol;

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LldpTlv {
    pub lldp_tlv_type: u8,  // 7 bits
    pub lldp_tlv_size: u16, // 9 bits
    pub lldp_tlv_octets: Vec<u8>,
}

impl LldpTlv {
    pub fn new(tlv_type: u8, tlv_data: &[u8]) -> PacketResult<Self> {
        if tlv_type & 0x80 != 0 {
            return Err(crate::invalid_error("Invalid tlv_type"));
        }

        let tlv_size = tlv_data.len();
        if tlv_size > 511 {
            return Err(crate::invalid_error("tlv_data exceeds 511 octets"));
        }
        Ok(LldpTlv {
            lldp_tlv_type: tlv_type,
            lldp_tlv_size: tlv_size as u16,
            lldp_tlv_octets: tlv_data.into(),
        })
    }

    fn deparse_into(&self, mut v: bytes::BytesMut) -> bytes::BytesMut {
        v.put_u16((self.lldp_tlv_type as u16) << 9 | self.lldp_tlv_size);
        v.put_slice(&self.lldp_tlv_octets);
        v
    }

    fn parse(pb: &mut crate::pbuf::ParseBuffer) -> PacketResult<LldpTlv> {
        if pb.bytes_left() < 2 {
            return Err(crate::parse_error(pb, "lldp tlv prefix too short"));
        }

        let ts = pb.get_u16();
        let lldp_tlv_type = (ts >> 9) as u8;
        let lldp_tlv_size = ts & 0x1ff;

        if lldp_tlv_size as usize > pb.left() {
            return Err(crate::parse_error(pb, "lldp tlv too short"));
        }
        let lldp_tlv_octets = pb.get_bytes(lldp_tlv_size as usize);

        Ok(LldpTlv {
            lldp_tlv_type,
            lldp_tlv_size,
            lldp_tlv_octets,
        })
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LldpHdr {
    pub lldp_data: Vec<LldpTlv>,
}

impl LldpHdr {
    fn size(&self) -> usize {
        let mut sz = 0;
        for tlv in &self.lldp_data {
            sz += 2 + tlv.lldp_tlv_size;
        }
        sz as usize
    }
}

impl Protocol for LldpHdr {
    fn parse(pb: &mut crate::pbuf::ParseBuffer) -> PacketResult<Headers> {
        let mut lldp_data = Vec::new();

        while pb.left() > 0 {
            let tlv = LldpTlv::parse(pb)?;
            let sz = tlv.lldp_tlv_size;
            lldp_data.push(tlv);
            if sz == 0 {
                break;
            }
        }

        if lldp_data.is_empty() {
            Err(crate::parse_error(pb, "lldp packet has no data"))
        } else {
            let mut hdrs = Headers::new();
            let hdr = LldpHdr { lldp_data };
            hdrs.lldp_hdr = Some(hdr);
            Ok(hdrs)
        }
    }

    fn gen(
        _src: Endpoint,
        _dst: Endpoint,
        protos: Vec<u16>,
        body: Option<&[u8]>,
    ) -> PacketResult<Packet> {
        if !protos.is_empty() {
            Err(crate::construct_error(
                "an LLDP header must be the final protocol",
            ))
        } else if body.is_some() {
            Err(crate::construct_error("an LLDP packet has no body"))
        } else {
            let h = LldpHdr {
                lldp_data: Vec::new(),
            };
            let mut pkt = Packet::new(None);
            pkt.hdrs.lldp_hdr = Some(h);
            pkt.hdrs.bytes += 9;

            Ok(pkt)
        }
    }

    fn deparse(pkt: &Packet, mut _hdr_size: usize) -> PacketResult<BytesMut> {
        let lldp_hdr = pkt.hdrs.lldp_hdr.as_ref().unwrap();
        let total_size = lldp_hdr.size() + 2;

        let mut v = if pkt.hdrs.eth_hdr.is_some() {
            crate::eth::EthHdr::deparse(pkt, total_size)?
        } else {
            BytesMut::with_capacity(total_size)
        };

        for tlv in &lldp_hdr.lldp_data {
            v = tlv.deparse_into(v);
        }
        v = LldpTlv::new(0, &[])?.deparse_into(v);

        Ok(v)
    }

    fn header_size(packet: &Packet) -> usize {
        match &packet.hdrs.lldp_hdr {
            Some(lldp_hdr) => lldp_hdr.size(),
            None => 0,
        }
    }

    fn doc(&self) -> (Option<String>, Option<String>, Option<String>) {
        (None, None, Some("lldp packet".to_string()))
    }
}

pub fn add_tlv(
    packet: &mut Packet,
    tlv_type: impl Into<u8>,
    tlv_data: &[u8],
) -> PacketResult<()> {
    if let Some(lldp) = &mut packet.hdrs.lldp_hdr {
        lldp.lldp_data
            .push(LldpTlv::new(tlv_type.into(), tlv_data)?);
        packet.hdrs.bytes += tlv_data.len() + 2;
        Ok(())
    } else {
        Err(crate::invalid_error("no LLDP header present"))
    }
}

impl fmt::Display for LldpHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LLDP packet")?;
        for tlv in &self.lldp_data {
            write!(
                f,
                "  tlv ({}), size {}: {:?}",
                tlv.lldp_tlv_type, tlv.lldp_tlv_size, tlv.lldp_tlv_octets
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
use hex_literal::hex;

#[test]
fn test_lldp_parse() {
    let bytes = hex!(
        "
        0180 c200 000e 0007 436c f0d7 88cc 0207
        0400 0743 6cf0 d704 0703 0007 436c f0d7
        0602 0078 fe19 0080 c209 8000 0100 0032
        3200 0000 0000 0002 0202 0202 0202 02fe
        0600 80c2 0b88 08fe 0500 80c2 0c00 0000
    "
    );

    let p = Packet::parse(&bytes).unwrap();

    let hdr = match p.hdrs.lldp_hdr {
        Some(hdr) => hdr,
        None => panic!("no lldp header found"),
    };
    assert_eq!(hdr.lldp_data.len(), 7);

    let expected = [
        (1, 7),    // chassis ID
        (2, 7),    // port ID ID
        (3, 2),    // ttl
        (127, 25), // ETS config
        (127, 6),  // flow control
        (127, 5),  // application protocl
        (0, 0),    // end of LLDPU
    ];

    for (idx, case) in expected.iter().enumerate() {
        assert_eq!(hdr.lldp_data[idx].lldp_tlv_type, case.0);
        assert_eq!(hdr.lldp_data[idx].lldp_tlv_size, case.1);
    }
}
