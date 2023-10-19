// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    utils::{pad_to_4bytes, parser::*, u32_from_be_bytes},
    RtcpPacket, RtcpParseError,
};

/// A Parsed Sdes packet.
#[derive(Debug, PartialEq, Eq)]
pub struct Sdes<'a> {
    data: &'a [u8],
    chunks: Vec<SdesChunk<'a>>,
}

impl<'a> RtcpPacket for Sdes<'a> {
    const MIN_PACKET_LEN: usize = 4;
    const PACKET_TYPE: u8 = 202;
}

impl<'a> Sdes<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        check_packet::<Self>(data)?;

        let mut chunks = vec![];
        if data.len() > Self::MIN_PACKET_LEN {
            let mut offset = Self::MIN_PACKET_LEN;

            while offset < data.len() {
                let (chunk, end) = SdesChunk::parse(&data[offset..])?;
                offset += end;
                chunks.push(chunk);
            }
        }

        Ok(Self { data, chunks })
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

    pub fn chunks(&'a self) -> impl Iterator<Item = &'a SdesChunk<'a>> {
        self.chunks.iter()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct SdesChunk<'a> {
    ssrc: u32,
    items: Vec<SdesItem<'a>>,
}

impl<'a> SdesChunk<'a> {
    const MIN_LEN: usize = 4;

    fn new(ssrc: u32) -> Self {
        Self {
            ssrc,
            items: Vec::new(),
        }
    }

    fn parse(data: &'a [u8]) -> Result<(Self, usize), RtcpParseError> {
        if data.len() < Self::MIN_LEN {
            return Err(RtcpParseError::Truncated {
                expected: Self::MIN_LEN,
                actual: data.len(),
            });
        }

        let mut ret = Self::new(u32_from_be_bytes(&data[0..4]));

        let mut offset = Self::MIN_LEN;
        if data.len() > Self::MIN_LEN {
            while offset < data.len() {
                if data[offset] == 0 {
                    offset += 1;
                    break;
                }

                let (item, end) = SdesItem::parse(&data[offset..])?;
                offset += end;
                ret.items.push(item);
            }

            while offset < data.len() && data[offset] == 0 {
                offset += 1;
            }
        }

        if pad_to_4bytes(offset) != offset {
            return Err(RtcpParseError::Truncated {
                expected: pad_to_4bytes(offset),
                actual: offset,
            });
        }

        Ok((ret, offset))
    }

    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    pub fn length(&self) -> usize {
        let len = Self::MIN_LEN + self.items.iter().fold(0, |acc, item| acc + item.length());
        pad_to_4bytes(len)
    }

    pub fn items(&'a self) -> impl Iterator<Item = &'a SdesItem<'a>> {
        self.items.iter()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct SdesItem<'a> {
    data: &'a [u8],
}

impl<'a> SdesItem<'a> {
    const MIN_LEN: usize = 4;
    const VALUE_MAX_LEN: u8 = 255;
    pub const CNAME: u8 = 0x01;
    pub const NAME: u8 = 0x02;
    pub const EMAIL: u8 = 0x03;
    pub const PHONE: u8 = 0x04;
    pub const LOC: u8 = 0x05;
    pub const TOOL: u8 = 0x06;
    pub const NOTE: u8 = 0x07;
    pub const PRIV: u8 = 0x08;

    fn parse(data: &'a [u8]) -> Result<(Self, usize), RtcpParseError> {
        if data.len() < Self::MIN_LEN {
            return Err(RtcpParseError::Truncated {
                expected: Self::MIN_LEN,
                actual: data.len(),
            });
        }

        let length = data[1] as usize;
        let end = 2 + length;
        if end > data.len() {
            return Err(RtcpParseError::Truncated {
                expected: end,
                actual: data.len(),
            });
        }

        if length > Self::VALUE_MAX_LEN as usize {
            return Err(RtcpParseError::SdesValueTooLarge {
                len: length,
                max: Self::VALUE_MAX_LEN,
            });
        }

        let item = Self { data: &data[..end] };

        if item.type_() == Self::PRIV {
            let prefix_len = item.priv_prefix_len();
            let value_offset = item.priv_value_offset();

            if value_offset as usize > data.len() {
                return Err(RtcpParseError::SdesPrivPrefixTooLarge {
                    len: prefix_len,
                    available: length as u8 - 1,
                });
            }
        }

        Ok((item, end))
    }

    pub fn type_(&self) -> u8 {
        self.data[0]
    }

    pub fn length(&self) -> usize {
        self.data[1] as usize
    }

    pub fn value(&self) -> &[u8] {
        if self.type_() == Self::PRIV {
            let offset = self.priv_value_offset() as usize;
            &self.data[offset..]
        } else {
            &self.data[2..]
        }
    }

    /// Gets the prefix length of this PRIV SDES Item.
    ///
    /// # Panic
    ///
    /// Panics if the SDES Iem is no a PRIV.
    pub fn priv_prefix_len(&self) -> u8 {
        if self.type_() != Self::PRIV {
            panic!("Item is not a PRIV");
        }

        self.data[2]
    }

    fn priv_value_offset(&self) -> u8 {
        debug_assert!(self.type_() == Self::PRIV);
        self.priv_prefix_len() + 3
    }

    /// Gets the prefix of this PRIV SDES Item.
    ///
    /// # Panic
    ///
    /// Panics if the SDES Iem is no a PRIV.
    pub fn priv_prefix(&self) -> &[u8] {
        if self.type_() != Self::PRIV {
            panic!("Item is not a PRIV");
        }

        &self.data[3..3 + self.priv_prefix_len() as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_sdes_chunk() {
        let (chunk, _) =
            SdesChunk::parse(&[0x00, 0x01, 0x02, 0x03, 0x01, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(chunk.ssrc(), 0x00010203);

        let mut items = chunk.items();
        let item = items.next().unwrap();
        assert_eq!(item.type_(), SdesItem::CNAME);
        assert!(item.value().is_empty());

        assert!(items.next().is_none());
    }

    #[test]
    fn parse_empty_sdes() {
        let data = [0x80, 0xca, 0x00, 0x00];
        let sdes = Sdes::parse(&data).unwrap();
        assert_eq!(sdes.version(), 2);
        assert_eq!(sdes.count(), 0);
        assert_eq!(sdes.chunks().count(), 0);
    }

    #[test]
    fn parse_cname_sdes() {
        let data = [
            0x81, 0xca, 0x00, 0x02, 0x91, 0x82, 0x73, 0x64, 0x01, 0x02, 0x30, 0x31,
        ];
        let sdes = Sdes::parse(&data).unwrap();
        assert_eq!(sdes.version(), 2);
        assert_eq!(sdes.count(), 1);

        let mut chunks = sdes.chunks();
        let chunk = chunks.next().unwrap();
        assert_eq!(chunk.ssrc(), 0x91827364);

        let mut items = chunk.items();
        let item = items.next().unwrap();
        assert_eq!(item.type_(), SdesItem::CNAME);
        assert_eq!(item.value(), &[0x30, 0x31]);

        assert!(items.next().is_none());
    }

    #[test]
    fn parse_cname_name_single_sdes_chunk() {
        let data = [
            0x81, 0xca, 0x00, 0x0c, 0x12, 0x34, 0x56, 0x78, 0x01, 0x05, 0x63, 0x6e, 0x61, 0x6d,
            0x65, 0x02, 0x09, 0x46, 0x72, 0x61, 0x6e, 0xc3, 0xa7, 0x6f, 0x69, 0x73, 0x08, 0x16,
            0x0b, 0x70, 0x72, 0x69, 0x76, 0x2d, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x70, 0x72,
            0x69, 0x76, 0x2d, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x00, 0x00,
        ];
        let sdes = Sdes::parse(&data).unwrap();
        assert_eq!(sdes.version(), 2);
        assert_eq!(sdes.count(), 1);

        let mut chunks = sdes.chunks();
        let chunk = chunks.next().unwrap();
        assert_eq!(chunk.ssrc(), 0x12345678);

        let mut items = chunk.items();

        let item = items.next().unwrap();
        assert_eq!(item.type_(), SdesItem::CNAME);
        assert_eq!(item.value(), b"cname");

        let item = items.next().unwrap();
        assert_eq!(item.type_(), SdesItem::NAME);
        assert_eq!(
            item.value(),
            &[0x46, 0x72, 0x61, 0x6e, 0xc3, 0xa7, 0x6f, 0x69, 0x73]
        );

        let item = items.next().unwrap();
        assert_eq!(item.type_(), SdesItem::PRIV);
        assert_eq!(item.priv_prefix(), b"priv-prefix");
        assert_eq!(item.value(), b"priv-value");

        assert!(items.next().is_none());
    }

    #[test]
    fn parse_multiple_sdes_chunks() {
        let data = [
            0x82, 0xca, 0x00, 0x0e, 0x12, 0x34, 0x56, 0x78, 0x01, 0x05, 0x63, 0x6e, 0x61, 0x6d,
            0x65, 0x02, 0x09, 0x46, 0x72, 0x61, 0x6e, 0xc3, 0xa7, 0x6f, 0x69, 0x73, 0x00, 0x00,
            0x34, 0x56, 0x78, 0x9a, 0x03, 0x09, 0x75, 0x73, 0x65, 0x72, 0x40, 0x68, 0x6f, 0x73,
            0x74, 0x04, 0x0c, 0x2b, 0x33, 0x33, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
            0x34, 0x00, 0x00, 0x00,
        ];
        let sdes = Sdes::parse(&data).unwrap();
        assert_eq!(sdes.version(), 2);
        assert_eq!(sdes.count(), 2);

        let mut chunks = sdes.chunks();
        let chunk = chunks.next().unwrap();
        assert_eq!(chunk.ssrc(), 0x12345678);

        let mut items = chunk.items();

        let item = items.next().unwrap();
        assert_eq!(item.type_(), SdesItem::CNAME);
        assert_eq!(item.value(), b"cname");

        let item = items.next().unwrap();
        assert_eq!(item.type_(), SdesItem::NAME);
        assert_eq!(
            item.value(),
            &[0x46, 0x72, 0x61, 0x6e, 0xc3, 0xa7, 0x6f, 0x69, 0x73]
        );

        let chunk = chunks.next().unwrap();
        assert_eq!(chunk.ssrc(), 0x3456789a);

        let mut items = chunk.items();

        let item = items.next().unwrap();
        assert_eq!(item.type_(), SdesItem::EMAIL);
        assert_eq!(item.value(), b"user@host");

        let item = items.next().unwrap();
        assert_eq!(item.type_(), SdesItem::PHONE);
        assert_eq!(item.value(), b"+33678901234");

        assert!(items.next().is_none());
    }
}
