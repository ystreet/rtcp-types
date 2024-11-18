// SPDX-License-Identifier: MIT OR Apache-2.0

use std::borrow::Cow;
use std::marker::PhantomData;

use crate::{
    prelude::*,
    utils::{pad_to_4bytes, parser, u32_from_be_bytes, writer},
    RtcpPacket, RtcpParseError, RtcpWriteError,
};

/// A Parsed Sdes packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sdes<'a> {
    data: &'a [u8],
    chunks: Vec<SdesChunk<'a>>,
}

impl<'a> RtcpPacket for Sdes<'a> {
    const MIN_PACKET_LEN: usize = 4;
    const PACKET_TYPE: u8 = 202;
}

impl<'a> RtcpPacketParser<'a> for Sdes<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        parser::check_packet::<Self>(data)?;

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

    #[inline(always)]
    fn header_data(&self) -> [u8; 4] {
        self.data[..4].try_into().unwrap()
    }
}

impl<'a> Sdes<'a> {
    /// The (optional) padding used by this [`Sdes`] packet
    pub fn padding(&self) -> Option<u8> {
        parser::parse_padding(self.data)
    }

    /// The chunks contained in this SDES
    pub fn chunks(&'a self) -> impl Iterator<Item = &'a SdesChunk<'a>> {
        self.chunks.iter()
    }

    /// Create a new [`SdesBuilder`]
    pub fn builder() -> SdesBuilder<'a> {
        SdesBuilder::default()
    }
}

/// A SDES chunk containing a single SSRC with possibly multiple SDES items
#[derive(Clone, Debug, PartialEq, Eq)]
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

    /// The SSRC that this chunk describes
    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// The length of this chunk
    pub fn length(&self) -> usize {
        let len = Self::MIN_LEN + self.items.iter().fold(0, |acc, item| acc + item.length());
        pad_to_4bytes(len)
    }

    /// The items in this chunk
    pub fn items(&'a self) -> impl Iterator<Item = &'a SdesItem<'a>> {
        self.items.iter()
    }

    /// Create a new [`SdesChunkBuilder`]
    pub fn builder(ssrc: u32) -> SdesChunkBuilder<'a> {
        SdesChunkBuilder::new(ssrc)
    }
}

/// An SDES item
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdesItem<'a> {
    data: &'a [u8],
}

impl<'a> SdesItem<'a> {
    const MIN_LEN: usize = 4;
    const VALUE_MAX_LEN: u8 = 255;
    /// The CNAME item in a SDES.
    pub const CNAME: u8 = 0x01;
    /// The NAME item in a SDES.
    pub const NAME: u8 = 0x02;
    /// The EMAIL item in a SDES.
    pub const EMAIL: u8 = 0x03;
    /// The PHONE item in a SDES.
    pub const PHONE: u8 = 0x04;
    /// The LOC item in a SDES.
    pub const LOC: u8 = 0x05;
    /// The TOOL item in a SDES.
    pub const TOOL: u8 = 0x06;
    /// The NOTE item in a SDES.
    pub const NOTE: u8 = 0x07;
    /// The PRIV item in a SDES.
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
            if item.data.len() < 3 {
                return Err(RtcpParseError::Truncated {
                    expected: 3,
                    actual: item.data.len(),
                });
            }
            let prefix_len = item.priv_prefix_len();
            let value_offset = item.priv_value_offset();

            if value_offset as usize > data.len() {
                return Err(RtcpParseError::SdesPrivPrefixTooLarge {
                    len: prefix_len as usize,
                    available: length as u8 - 1,
                });
            }
        }

        Ok((item, end))
    }

    /// The type of this item
    pub fn type_(&self) -> u8 {
        self.data[0]
    }

    /// The length of this item
    pub fn length(&self) -> usize {
        self.data[1] as usize
    }

    /// The value of this item
    pub fn value(&self) -> &[u8] {
        if self.type_() == Self::PRIV {
            let offset = self.priv_value_offset() as usize;
            &self.data[offset..]
        } else {
            &self.data[2..]
        }
    }

    /// The value of this item as a string
    pub fn get_value_string(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.value().into())
    }

    /// Gets the prefix length of this PRIV SDES Item.
    ///
    /// # Panic
    ///
    /// Panics if the SDES Iem is not a PRIV.
    pub fn priv_prefix_len(&self) -> u8 {
        if self.type_() != Self::PRIV {
            panic!("Item is not a PRIV");
        }

        self.data[2]
    }

    fn priv_value_offset(&self) -> u16 {
        debug_assert!(self.type_() == Self::PRIV);
        self.priv_prefix_len() as u16 + 3
    }

    /// Gets the prefix of this PRIV SDES Item.
    ///
    /// # Panic
    ///
    /// Panics if the SDES Iem is not a PRIV.
    pub fn priv_prefix(&self) -> &[u8] {
        if self.type_() != Self::PRIV {
            panic!("Item is not a PRIV");
        }

        &self.data[3..3 + self.priv_prefix_len() as usize]
    }

    /// Create a new [`SdesItemBuilder`]
    pub fn builder(type_: u8, value: &'a str) -> SdesItemBuilder<'a> {
        SdesItemBuilder::new(type_, value)
    }
}

/// SDES packet Builder
#[derive(Debug, Default)]
#[must_use = "The builder must be built to be used"]
pub struct SdesBuilder<'a> {
    padding: u8,
    chunks: Vec<SdesChunkBuilder<'a>>,
    phantom: PhantomData<&'a SdesChunkBuilder<'a>>,
}

impl<'a> SdesBuilder<'a> {
    /// Sets the number of padding bytes to use for this App.
    pub fn padding(mut self, padding: u8) -> Self {
        self.padding = padding;
        self
    }

    /// Adds the provided [`SdesChunk`].
    pub fn add_chunk(mut self, chunk: SdesChunkBuilder<'a>) -> Self {
        self.chunks.push(chunk);
        self
    }
}

impl<'a> RtcpPacketWriter for SdesBuilder<'a> {
    /// Calculates the size required to write this App packet.
    ///
    /// Returns an error if:
    ///
    /// * An Item presents an invalid size.
    fn calculate_size(&self) -> Result<usize, RtcpWriteError> {
        if self.chunks.len() > Sdes::MAX_COUNT as usize {
            return Err(RtcpWriteError::TooManySdesChunks {
                count: self.chunks.len(),
                max: Sdes::MAX_COUNT,
            });
        }

        writer::check_padding(self.padding)?;

        let mut chunks_size = 0;
        for chunk in self.chunks.iter() {
            chunks_size += chunk.calculate_size()?;
        }

        Ok(Sdes::MIN_PACKET_LEN + chunks_size + self.padding as usize)
    }

    /// Writes this Sdes packet chunks into `buf` without any validity checks.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Panic
    ///
    /// Panics if the buf is not large enough.
    #[inline]
    fn write_into_unchecked(&self, buf: &mut [u8]) -> usize {
        let mut idx =
            writer::write_header_unchecked::<Sdes>(self.padding, self.chunks.len() as u8, buf);

        for chunk in self.chunks.iter() {
            idx += chunk.write_into_unchecked(&mut buf[idx..]);
        }

        idx += writer::write_padding_unchecked(self.padding, &mut buf[idx..]);

        idx
    }

    fn get_padding(&self) -> Option<u8> {
        if self.padding == 0 {
            return None;
        }

        Some(self.padding)
    }
}

/// SDES Chunk Builder
#[derive(Debug)]
#[must_use = "The builder must be built to be used"]
pub struct SdesChunkBuilder<'a> {
    ssrc: u32,
    items: Vec<SdesItemBuilder<'a>>,
    phantom: PhantomData<&'a SdesItemBuilder<'a>>,
}

impl<'a> SdesChunkBuilder<'a> {
    fn new(ssrc: u32) -> Self {
        SdesChunkBuilder {
            ssrc,
            items: Vec::new(),
            phantom: PhantomData,
        }
    }

    /// Add an item to this chunk
    pub fn add_item(mut self, item: SdesItemBuilder<'a>) -> Self {
        self.items.push(item);
        self
    }

    /// Calculates the size required to write this App packet.
    ///
    /// Returns an error if:
    ///
    /// * An Item presents an invalid size.
    fn calculate_size(&self) -> Result<usize, RtcpWriteError> {
        let mut items_size = 0;
        for item in self.items.iter() {
            items_size += item.calculate_size()?;
        }

        Ok(pad_to_4bytes(4 + items_size + 1))
    }

    /// Writes this [`SdesChunk`] into `buf` without checking the buffer size.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Panic
    ///
    /// Panics if the buf is not large enough.
    #[inline]
    fn write_into_unchecked(&self, buf: &mut [u8]) -> usize {
        buf[0..4].copy_from_slice(&self.ssrc.to_be_bytes());

        let mut idx = 4;
        for item in self.items.iter() {
            idx += item.write_into_unchecked(&mut buf[idx..]);
        }

        // always have at least one padding nul byte at the end so it is possible to determine the
        // end of this chunk
        let end = pad_to_4bytes(idx + 1);
        if end > idx {
            buf[idx..end].fill(0);
        }

        end
    }

    /// Writes the SDES Chunk into `buf`.
    ///
    /// Returns an error if:
    ///
    /// * The buffer is too small.
    /// * An Item generated an error.
    pub fn write_into(&self, buf: &mut [u8]) -> Result<usize, RtcpWriteError> {
        let req_size = self.calculate_size()?;
        if buf.len() < req_size {
            return Err(RtcpWriteError::OutputTooSmall(req_size));
        }

        Ok(self.write_into_unchecked(&mut buf[..req_size]))
    }

    /// Adds an item transforming it into an owned version first.
    ///
    /// Lifetime of `self` is unchanged even if `item` is shorter lived.
    pub fn add_item_owned(mut self, item: SdesItemBuilder<'_>) -> Self {
        self.items.push(item.into_owned());
        self
    }
}

/// SDES item builder
#[derive(Debug)]
#[must_use = "The builder must be built to be used"]
pub struct SdesItemBuilder<'a> {
    type_: u8,
    prefix: Cow<'a, [u8]>,
    value: Cow<'a, str>,
}

impl<'a> SdesItemBuilder<'a> {
    fn new(type_: u8, value: impl Into<Cow<'a, str>>) -> SdesItemBuilder<'a> {
        SdesItemBuilder {
            type_,
            prefix: Default::default(),
            value: value.into(),
        }
    }

    /// Adds a prefix to a PRIV SDES Item.
    ///
    /// Has no effect if the type is not `SdesItem::PRIV`.
    pub fn prefix(mut self, prefix: impl Into<Cow<'a, [u8]>>) -> Self {
        self.prefix = prefix.into();
        self
    }

    /// Calculates the size required to write this App packet.
    ///
    /// Returns an error if:
    ///
    /// * An Item presents an invalid size.
    fn calculate_size(&self) -> Result<usize, RtcpWriteError> {
        let value_len = self.value.as_bytes().len();

        if self.type_ == SdesItem::PRIV {
            // Note RFC 3550 p. 42 doesn't specify the encoding for the prefix "string".
            // We decided to allow any byte sequence with compliant length.

            let prefix_len = self.prefix.len();

            if prefix_len + 1 > SdesItem::VALUE_MAX_LEN as usize {
                return Err(RtcpWriteError::SdesPrivPrefixTooLarge {
                    len: prefix_len,
                    max: SdesItem::VALUE_MAX_LEN - 1,
                });
            }

            if prefix_len + 1 + value_len > SdesItem::VALUE_MAX_LEN as usize {
                return Err(RtcpWriteError::SdesValueTooLarge {
                    len: value_len,
                    max: SdesItem::VALUE_MAX_LEN - 1 - prefix_len as u8,
                });
            }

            Ok(3 + prefix_len + value_len)
        } else {
            if value_len > SdesItem::VALUE_MAX_LEN as usize {
                return Err(RtcpWriteError::SdesValueTooLarge {
                    len: value_len,
                    max: SdesItem::VALUE_MAX_LEN,
                });
            }

            Ok(2 + value_len)
        }
    }

    /// Writes this [`SdesChunk`] into `buf` without any validity checks.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Panic
    ///
    /// Panics if the buf is not large enough.
    #[inline]
    fn write_into_unchecked(&self, buf: &mut [u8]) -> usize {
        let value = self.value.as_bytes();
        let value_len = value.len();

        buf[0] = self.type_;

        let mut end;
        if self.type_ == SdesItem::PRIV {
            let prefix_len = self.prefix.len();

            buf[1] = (prefix_len + 1 + value_len) as u8;

            buf[2] = prefix_len as u8;
            end = prefix_len + 3;
            buf[3..end].copy_from_slice(&self.prefix);

            let idx = end;
            end += value_len;
            buf[idx..end].copy_from_slice(value);
        } else {
            buf[1] = value_len as u8;
            end = value.len() + 2;
            buf[2..end].copy_from_slice(value);
        }

        end
    }

    /// Writes the SDES Item into `buf`.
    ///
    /// Returns an error if:
    ///
    /// * The buffer is too small.
    /// * An Item presents an invalid size.
    pub fn write_into(&self, buf: &mut [u8]) -> Result<usize, RtcpWriteError> {
        let req_size = self.calculate_size()?;
        if buf.len() < req_size {
            return Err(RtcpWriteError::OutputTooSmall(req_size));
        }

        Ok(self.write_into_unchecked(&mut buf[..req_size]))
    }

    /// Converts this `SdesItemBuilder` into an owned version.
    ///
    /// Clones the `value` (and `prefix` if applicable) if it is not already owned.
    pub fn into_owned(self) -> SdesItemBuilder<'static> {
        SdesItemBuilder {
            type_: self.type_,
            prefix: self.prefix.into_owned().into(),
            value: self.value.into_owned().into(),
        }
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
    fn sdes_item_multiple_of_4_has_zero_terminating() {
        let ssrcs = [0x98765432, 0x67892345];
        let sdes = Sdes::builder()
            .add_chunk(
                SdesChunk::builder(ssrcs[0]).add_item(SdesItem::builder(SdesItem::CNAME, "ab")),
            )
            .add_chunk(
                SdesChunk::builder(ssrcs[1]).add_item(SdesItem::builder(SdesItem::CNAME, "cd")),
            );
        let mut data = [0; 256];
        let len = sdes.write_into(&mut data).unwrap();
        let data = &data[..len];
        let parsed = Sdes::parse(data).unwrap();
        for c in parsed.chunks() {
            assert!(ssrcs.contains(&c.ssrc()));
        }
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
        assert_eq!(item.get_value_string().unwrap(), "cname");

        let item = items.next().unwrap();
        assert_eq!(item.type_(), SdesItem::NAME);
        assert_eq!(
            item.value(),
            &[0x46, 0x72, 0x61, 0x6e, 0xc3, 0xa7, 0x6f, 0x69, 0x73]
        );
        assert_eq!(item.get_value_string().unwrap(), "François");

        let item = items.next().unwrap();
        assert_eq!(item.type_(), SdesItem::PRIV);
        assert_eq!(item.priv_prefix(), b"priv-prefix");
        assert_eq!(item.value(), b"priv-value");
        assert_eq!(item.get_value_string().unwrap(), "priv-value");

        assert!(items.next().is_none());
    }

    #[test]
    fn build_cname_name_single_sdes_chunk() {
        let chunk1 = SdesChunk::builder(0x12345678)
            .add_item(SdesItem::builder(SdesItem::CNAME, "cname"))
            .add_item(SdesItem::builder(SdesItem::NAME, "François"))
            .add_item(
                SdesItem::builder(SdesItem::PRIV, "priv-value").prefix(b"priv-prefix".as_ref()),
            );

        const REQ_LEN: usize = Sdes::MIN_PACKET_LEN
            + SdesChunk::MIN_LEN
            + pad_to_4bytes(
                2 + "cname".len()
                    + 2
                    + "François".as_bytes().len()
                    + 3
                    + "priv-prefix".len()
                    + "priv-value".len(),
            );

        let sdesb = Sdes::builder().add_chunk(chunk1);
        let req_len = sdesb.calculate_size().unwrap();
        assert_eq!(req_len, REQ_LEN);
        let mut data = [0; REQ_LEN];

        let len = sdesb.write_into(&mut data).unwrap();
        assert_eq!(len, REQ_LEN);
        assert_eq!(
            data,
            [
                0x81, 0xca, 0x00, 0x0c, 0x12, 0x34, 0x56, 0x78, 0x01, 0x05, 0x63, 0x6e, 0x61, 0x6d,
                0x65, 0x02, 0x09, 0x46, 0x72, 0x61, 0x6e, 0xc3, 0xa7, 0x6f, 0x69, 0x73, 0x08, 0x16,
                0x0b, 0x70, 0x72, 0x69, 0x76, 0x2d, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x70, 0x72,
                0x69, 0x76, 0x2d, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x00, 0x00,
            ]
        );
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

    #[test]
    fn build_multiple_sdes_chunks() {
        let chunk1 = SdesChunk::builder(0x12345678)
            .add_item(SdesItem::builder(SdesItem::CNAME, "cname"))
            .add_item(SdesItem::builder(SdesItem::NAME, "François"));

        let chunk2 = SdesChunk::builder(0x3456789a)
            .add_item(SdesItem::builder(SdesItem::EMAIL, "user@host"))
            .add_item(SdesItem::builder(SdesItem::PHONE, "+33678901234"));

        const REQ_LEN: usize = Sdes::MIN_PACKET_LEN
            + SdesChunk::MIN_LEN
            + pad_to_4bytes(2 + "cname".len() + 2 + "François".as_bytes().len())
            + SdesChunk::MIN_LEN
            + pad_to_4bytes(2 + "user@host".len() + 2 + "+33678901234".len());

        let sdesb = Sdes::builder().add_chunk(chunk1).add_chunk(chunk2);
        let req_len = sdesb.calculate_size().unwrap();
        assert_eq!(req_len, REQ_LEN);

        let mut data = [0; REQ_LEN];
        let len = sdesb.write_into(&mut data).unwrap();
        assert_eq!(len, REQ_LEN);
        assert_eq!(
            data,
            [
                0x82, 0xca, 0x00, 0x0e, 0x12, 0x34, 0x56, 0x78, 0x01, 0x05, 0x63, 0x6e, 0x61, 0x6d,
                0x65, 0x02, 0x09, 0x46, 0x72, 0x61, 0x6e, 0xc3, 0xa7, 0x6f, 0x69, 0x73, 0x00, 0x00,
                0x34, 0x56, 0x78, 0x9a, 0x03, 0x09, 0x75, 0x73, 0x65, 0x72, 0x40, 0x68, 0x6f, 0x73,
                0x74, 0x04, 0x0c, 0x2b, 0x33, 0x33, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
                0x34, 0x00, 0x00, 0x00,
            ]
        );
    }

    #[test]
    fn build_static_sdes() {
        const REQ_LEN: usize = Sdes::MIN_PACKET_LEN
            + SdesChunk::MIN_LEN
            + pad_to_4bytes(2 + 5 /* cname */ + 2 + 4 /* name */);

        let sdesb = {
            let cname = "cname".to_string();
            let name = "name".to_string();
            let chunk1 = SdesChunk::builder(0x12345678)
                .add_item(SdesItem::builder(SdesItem::CNAME, &cname).into_owned())
                .add_item_owned(SdesItem::builder(SdesItem::NAME, &name));

            Sdes::builder().add_chunk(chunk1)
        };

        let req_len = sdesb.calculate_size().unwrap();
        assert_eq!(req_len, REQ_LEN);

        let mut data = [0; REQ_LEN];
        let len = sdesb.write_into(&mut data).unwrap();
        assert_eq!(len, REQ_LEN);
        assert_eq!(
            data,
            [
                0x81, 0xca, 0x00, 0x05, 0x12, 0x34, 0x56, 0x78, 0x01, 0x05, 0x63, 0x6e, 0x61, 0x6d,
                0x65, 0x02, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x00, 0x00, 0x00,
            ]
        );
    }

    #[test]
    fn build_sdes_from_shorter_lived_item() {
        const REQ_LEN: usize = Sdes::MIN_PACKET_LEN
            + SdesChunk::MIN_LEN
            + pad_to_4bytes(2 + 5 /* cname */ + 2 + 4 /* name */);

        let mut data = [0; REQ_LEN];

        {
            let cname = "cname".to_string();
            let chunk1 = SdesChunk::builder(0x12345678)
                .add_item(SdesItem::builder(SdesItem::CNAME, cname.as_str()));

            let chunk1 = {
                // adding name which is shorter lived than chunk1
                let name = "name".to_string();
                chunk1.add_item_owned(SdesItem::builder(SdesItem::NAME, name.as_str()))
            };

            let sdesb = Sdes::builder().add_chunk(chunk1);

            let req_len = sdesb.calculate_size().unwrap();
            assert_eq!(req_len, REQ_LEN);

            let len = sdesb.write_into(&mut data).unwrap();
            assert_eq!(len, REQ_LEN);
        }

        assert_eq!(
            data,
            [
                0x81, 0xca, 0x00, 0x05, 0x12, 0x34, 0x56, 0x78, 0x01, 0x05, 0x63, 0x6e, 0x61, 0x6d,
                0x65, 0x02, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x00, 0x00, 0x00,
            ]
        );
    }

    #[test]
    fn build_too_many_chunks() {
        let mut b = Sdes::builder();
        for _ in 0..Sdes::MAX_COUNT as usize + 1 {
            b = b.add_chunk(SdesChunk::builder(0))
        }
        let err = b.calculate_size().unwrap_err();
        assert_eq!(
            err,
            RtcpWriteError::TooManySdesChunks {
                count: Sdes::MAX_COUNT as usize + 1,
                max: Sdes::MAX_COUNT,
            }
        );
    }

    #[test]
    fn build_item_value_too_large() {
        let value: String =
            String::from_utf8([b'a'; SdesItem::VALUE_MAX_LEN as usize + 1].into()).unwrap();
        let b = Sdes::builder()
            .add_chunk(SdesChunk::builder(0).add_item(SdesItem::builder(SdesItem::NAME, &value)));
        let err = b.calculate_size().unwrap_err();
        assert_eq!(
            err,
            RtcpWriteError::SdesValueTooLarge {
                len: SdesItem::VALUE_MAX_LEN as usize + 1,
                max: SdesItem::VALUE_MAX_LEN,
            }
        );
    }

    #[test]
    fn build_priv_item_prefix_too_large() {
        let prefix = vec![0x01; SdesItem::VALUE_MAX_LEN as usize];
        let b = Sdes::builder().add_chunk(
            SdesChunk::builder(0).add_item(SdesItem::builder(SdesItem::PRIV, "").prefix(&prefix)),
        );
        let err = b.calculate_size().unwrap_err();
        assert_eq!(
            err,
            RtcpWriteError::SdesPrivPrefixTooLarge {
                len: SdesItem::VALUE_MAX_LEN as usize,
                max: SdesItem::VALUE_MAX_LEN - 1,
            }
        );
    }

    #[test]
    fn build_priv_item_value_too_large() {
        let value: String =
            String::from_utf8([b'a'; SdesItem::VALUE_MAX_LEN as usize].into()).unwrap();
        let b = Sdes::builder()
            .add_chunk(SdesChunk::builder(0).add_item(SdesItem::builder(SdesItem::PRIV, &value)));
        let err = b.calculate_size().unwrap_err();
        assert_eq!(
            err,
            RtcpWriteError::SdesValueTooLarge {
                len: SdesItem::VALUE_MAX_LEN as usize,
                max: SdesItem::VALUE_MAX_LEN - 1,
            }
        );
    }

    #[test]
    fn build_padding_not_multiple_4() {
        let b = Sdes::builder().padding(5);
        let err = b.calculate_size().unwrap_err();
        assert_eq!(err, RtcpWriteError::InvalidPadding { padding: 5 });
    }
}
