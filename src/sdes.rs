// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    utils::{pad_to_4bytes, parser::*, u32_from_be_bytes},
    RtcpPacket, RtcpParseError,
};

/// A Parsed Sdes packet.
#[derive(Debug, PartialEq, Eq)]
pub struct Sdes<'a> {
    data: &'a [u8],
}

impl<'a> RtcpPacket for Sdes<'a> {
    const MIN_PACKET_LEN: usize = 4;
    const PACKET_TYPE: u8 = 202;
}

impl<'a> Sdes<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        check_packet::<Self>(data)?;
        Ok(Self { data })
    }

    pub fn padding(&self) -> Option<u8> {
        parse_padding(self.data)
    }

    pub fn version(&self) -> u8 {
        parse_version(self.data)
    }

    pub fn count(&self) -> u8 {
        parse_count(self.data)
    }

    pub fn length(&self) -> usize {
        parse_length(self.data)
    }

    pub fn items(&self) -> impl Iterator<Item = SdesItem<'a>> + '_ {
        SdesItemIter {
            data: &self.data[4..],
            offset: 0,
            n_items: self.count(),
            items_i: 0,
        }
    }
}

pub struct SdesItemIter<'a> {
    data: &'a [u8],
    offset: usize,
    n_items: u8,
    items_i: u8,
}

impl<'a> Iterator for SdesItemIter<'a> {
    type Item = SdesItem<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.items_i >= self.n_items {
            return None;
        }
        match SdesItem::parse(&self.data[self.offset..]) {
            Ok(item) => {
                self.offset += pad_to_4bytes(item.length() as usize + 6);
                self.items_i += 1;
                Some(item)
            }
            Err(_) => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct SdesItem<'a> {
    data: &'a [u8],
}

impl<'a> SdesItem<'a> {
    const MIN_PACKET_LEN: usize = 8;
    pub const CNAME: u8 = 0x01;
    pub const NAME: u8 = 0x02;
    pub const EMAIL: u8 = 0x03;
    pub const PHONE: u8 = 0x04;
    pub const LOC: u8 = 0x05;
    pub const TOOL: u8 = 0x06;
    pub const NOTE: u8 = 0x07;
    pub const PRIV: u8 = 0x08;

    fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        if data.len() < Self::MIN_PACKET_LEN {
            return Err(RtcpParseError::Truncated {
                expected: Self::MIN_PACKET_LEN,
                actual: data.len(),
            });
        }
        let ret = Self { data };
        if ret.length() as usize + 6 > data.len() {
            return Err(RtcpParseError::Truncated {
                expected: ret.length() as usize + 6,
                actual: data.len(),
            });
        }
        if pad_to_4bytes(data.len()) != data.len() {
            return Err(RtcpParseError::Truncated {
                expected: pad_to_4bytes(data.len()),
                actual: data.len(),
            });
        }
        Ok(ret)
    }

    pub fn ssrc(&self) -> u32 {
        u32_from_be_bytes(&self.data[0..4])
    }

    fn length(&self) -> u8 {
        self.data[5]
    }

    pub fn type_(&self) -> u8 {
        self.data[4]
    }

    pub fn value(&self) -> &[u8] {
        &self.data[6..6 + self.length() as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_sdes_item() {
        let item = SdesItem::parse(&[0x00, 0x01, 0x02, 0x03, 0x01, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(item.ssrc(), 0x00010203);
        assert_eq!(item.type_(), SdesItem::CNAME);
        assert_eq!(item.value(), &[]);
    }

    #[test]
    fn parse_empty_sdes() {
        let data = [0x80, 0xca, 0x00, 0x00];
        let sdes = Sdes::parse(&data).unwrap();
        assert_eq!(sdes.version(), 2);
        assert_eq!(sdes.count(), 0);
        assert_eq!(sdes.items().count(), 0);
    }

    #[test]
    fn parse_cname_sdes() {
        let data = [
            0x81, 0xca, 0x00, 0x02, 0x91, 0x82, 0x73, 0x64, 0x01, 0x02, 0x30, 0x31,
        ];
        let sdes = Sdes::parse(&data).unwrap();
        assert_eq!(sdes.version(), 2);
        assert_eq!(sdes.count(), 1);
        let mut items = sdes.items();
        let next = items.next().unwrap();
        assert_eq!(next.ssrc(), 0x91827364);
        assert_eq!(next.type_(), SdesItem::CNAME);
        assert_eq!(next.value(), &[0x30, 0x31]);
        assert_eq!(items.next(), None);
    }
}
