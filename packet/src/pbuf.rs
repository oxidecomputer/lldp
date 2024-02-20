use crate::MacAddr;
use std::net::{Ipv4Addr, Ipv6Addr};

pub struct ParseBuffer<'a> {
    data: &'a [u8],
    len: usize,
    byte: usize,
    bit: usize,
}

impl ParseBuffer<'_> {
    pub fn new_from_slice(d: &[u8]) -> ParseBuffer {
        ParseBuffer {
            data: d,
            byte: 0,
            bit: 0,
            len: d.len() * 8,
        }
    }

    pub fn offset(&self) -> usize {
        self.byte
    }

    pub fn byte_align(&mut self) {
        if self.bit != 0 {
            self.bit = 0;
            self.byte += 1;
        }
    }

    pub fn advance_bytes(&mut self, bytes: usize) {
        self.byte += bytes;
    }

    pub fn advance_bits(&mut self, bits: usize) {
        let bit = self.bit + bits;
        if bit > 8 {
            self.advance_bytes(bit / 8);
        }
        self.bit = bit % 8;
    }

    pub fn bytes_left(&mut self) -> usize {
        let consumed = (self.byte * 8) + self.bit;

        if consumed < self.len {
            ((self.len - consumed) / 8)
                - match self.bit {
                    0 => 0,
                    _ => 1,
                }
        } else {
            0
        }
    }
    pub fn left(&mut self) -> usize {
        let consumed = (self.byte * 8) + self.bit;

        if consumed < self.len {
            self.len - consumed
        } else {
            0
        }
    }

    fn get_chunk(&mut self, max: usize) -> (u32, usize) {
        if max > self.left() {
            panic!("buffer overrun");
        }

        let byte = self.byte;
        let bit = self.bit;
        let mut rval = self.data[byte] as u32;

        // simple case - return a single, aligned byte
        if bit == 0 && max > 8 {
            self.byte += 1;
            return (rval, 8);
        }

        // we're starting mid-byte, grab the unused bits in this byte
        let unused = 8 - bit;
        rval &= (1 << unused) - 1;

        // if the caller wants all of those bits, return them
        if max >= unused {
            self.byte += 1;
            self.bit = 0;
            return (rval, unused);
        }

        // shift the unwanted bits out of the buffer before returning the
        // result to the caller.
        rval >>= unused - max;
        self.bit += max;

        (rval, max)
    }

    pub fn get_bits(&mut self, len: usize) -> u32 {
        if len > 32 {
            panic!("too long");
        }

        let mut rval: u32 = 0;
        let mut left = len;
        while left > 0 {
            let (chunk, bits) = self.get_chunk(left);
            rval = rval << bits | chunk;
            left -= bits;
        }

        rval
    }

    pub fn get_bytes(&mut self, bytes: usize) -> Vec<u8> {
        self.byte_align();

        if self.left() < bytes * 8 {
            panic!("buffer overrun");
        }
        let mut v = Vec::new();
        v.extend_from_slice(&self.data[self.byte..self.byte + bytes]);
        self.byte += bytes;
        v
    }

    pub fn get_u32(&mut self) -> u32 {
        self.byte_align();

        if self.left() < 32 {
            panic!("buffer overrun");
        }

        let b = &self.data[self.byte..];
        self.byte += 4;

        (b[0] as u32) << 24 | (b[1] as u32) << 16 | (b[2] as u32) << 8 | (b[3] as u32)
    }

    pub fn get_u16(&mut self) -> u16 {
        self.byte_align();

        if self.left() < 16 {
            panic!("buffer overrun");
        }

        let b = &self.data[self.byte..];
        self.byte += 2;

        (b[0] as u16) << 8 | (b[1] as u16)
    }

    pub fn get_u8(&mut self) -> u8 {
        self.byte_align();

        if self.left() < 8 {
            panic!("buffer overrun");
        }

        let b = self.data[self.byte];
        self.byte += 1;

        b
    }

    pub fn get_flag(&mut self) -> bool {
        self.get_bits(1) == 1
    }

    pub fn get_mac(&mut self) -> MacAddr {
        let b = self.get_bytes(6);
        MacAddr::new(b[0], b[1], b[2], b[3], b[4], b[5])
    }

    pub fn get_ipv4(&mut self) -> Ipv4Addr {
        let x = self.get_bytes(4);
        Ipv4Addr::new(x[0], x[1], x[2], x[3])
    }

    pub fn get_ipv6(&mut self) -> Ipv6Addr {
        let x = self.get_bytes(16);
        let mut w = [0u16; 8];

        for i in 0..8 {
            w[i] = (x[2 * i] as u16) << 8 | (x[2 * i + 1] as u16);
        }

        Ipv6Addr::new(w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7])
    }
}

#[test]
fn test_byte() {
    let raw: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
    let mut tbuf = ParseBuffer::new_from_slice(&raw);

    assert_eq!(tbuf.get_u8(), 0x11);
    assert_eq!(tbuf.get_u8(), 0x22);
    assert_eq!(tbuf.get_u8(), 0x33);
    assert_eq!(tbuf.get_u8(), 0x44);
}

#[test]
fn test_short() {
    let raw: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
    let mut tbuf = ParseBuffer::new_from_slice(&raw);

    assert_eq!(tbuf.get_u16(), 0x1122);
    assert_eq!(tbuf.get_u16(), 0x3344);
}

#[test]
fn test_word() {
    let raw: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
    let mut tbuf = ParseBuffer::new_from_slice(&raw);

    assert_eq!(tbuf.get_u32(), 0x11223344);
}

#[test]
fn test_nibble() {
    let raw: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
    let mut tbuf = ParseBuffer::new_from_slice(&raw);

    assert_eq!(tbuf.get_bits(4), 0x1);
    assert_eq!(tbuf.get_bits(4), 0x1);
    assert_eq!(tbuf.get_bits(4), 0x2);
    assert_eq!(tbuf.get_bits(4), 0x2);
    assert_eq!(tbuf.get_bits(4), 0x3);
    assert_eq!(tbuf.get_bits(4), 0x3);
    assert_eq!(tbuf.get_bits(4), 0x4);
    assert_eq!(tbuf.get_bits(4), 0x4);
}

#[test]
fn test_twelve() {
    let raw: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
    let mut tbuf = ParseBuffer::new_from_slice(&raw);

    assert_eq!(tbuf.get_bits(12), 0x112);
    assert_eq!(tbuf.get_bits(12), 0x233);
}

#[test]
#[should_panic(expected = "buffer overrun")]
fn test_overflow() {
    let raw: [u8; 4] = [0x11, 0x22, 0x33, 0x44];
    let mut tbuf = ParseBuffer::new_from_slice(&raw);

    assert_eq!(tbuf.get_u32(), 0x11223344);
    tbuf.get_u32();
}
