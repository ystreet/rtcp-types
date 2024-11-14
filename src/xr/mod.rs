// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    prelude::*,
    utils::{pad_to_4bytes, parser, u16_from_be_bytes, writer},
    RtcpPacket, RtcpParseError, RtcpWriteError,
};

pub mod dlrr;
pub mod duplicate_rle;
pub mod loss_rle;
pub mod packet_receipt_time;
pub mod receiver_reference_time;
pub(crate) mod rle;

/// A parsed extended report packet as specified in RFC 3611.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Xr<'a> {
    data: &'a [u8],
}

impl<'a> RtcpPacket for Xr<'a> {
    const MIN_PACKET_LEN: usize = 12;
    const PACKET_TYPE: u8 = 207;
}

impl<'a> RtcpPacketParser<'a> for Xr<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        parser::check_packet::<Self>(data)?;
        let mut offset = 8;
        loop {
            if offset >= data.len() {
                break;
            }
            let block = XrBlock::parse(&data[offset..])?;
            offset += block.length();
        }
        Ok(Self { data })
    }

    #[inline(always)]
    fn header_data(&self) -> [u8; 4] {
        self.data[..4].try_into().unwrap()
    }
}

impl<'a> Xr<'a> {
    /// Constructs a [`XrBuilder`] which refers to the provided [`XrBlockBuilder`].
    pub fn builder() -> XrBuilder {
        XrBuilder {
            padding: 0,
            sender_ssrc: 0,
            blocks: vec![],
        }
    }

    /// The (optional) padding used by this [`Xr`] packet
    pub fn padding(&self) -> Option<u8> {
        parser::parse_padding(self.data)
    }

    /// The SSRC of the sender sending this feedback
    pub fn sender_ssrc(&self) -> u32 {
        parser::parse_ssrc(self.data)
    }

    /// Iterator over the individual blocks in the [`Xr`] packet.
    pub fn block_iter(&'a self) -> impl Iterator<Item = XrBlock<'a>> + 'a {
        XrBlockIter {
            xr: self,
            offset: 8,
        }
    }
    // TODO: add iterator
}

struct XrBlockIter<'a> {
    xr: &'a Xr<'a>,
    offset: usize,
}

impl<'a> Iterator for XrBlockIter<'a> {
    type Item = XrBlock<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset > self.xr.data.len() {
            return None;
        }
        let block = XrBlock::parse(&self.xr.data[self.offset..]).ok()?;
        self.offset += block.length();
        Some(block)
    }
}

/// XR packet builder
#[derive(Debug)]
#[must_use = "The builder must be built to be used"]
pub struct XrBuilder {
    padding: u8,
    sender_ssrc: u32,
    blocks: Vec<Box<dyn XrBlockBuilder<'static>>>,
}

impl XrBuilder {
    /// Set the SSRC this feedback packet is being sent from
    pub fn sender_ssrc(mut self, sender_ssrc: u32) -> Self {
        self.sender_ssrc = sender_ssrc;
        self
    }

    /// Sets the number of padding bytes to use for this [`Xr`] packet.
    pub fn padding(mut self, padding: u8) -> Self {
        self.padding = padding;
        self
    }

    pub fn add_block(mut self, block: impl XrBlockBuilder<'static> + 'static) -> XrBuilder {
        self.blocks.push(Box::new(block));
        self
    }
}

impl RtcpPacketWriter for XrBuilder {
    /// Calculates the size required to write this Xr packet.
    ///
    /// Returns an error if:
    ///
    /// * The report block data is too large
    /// * The report block fails to calculate a valid size
    fn calculate_size(&self) -> Result<usize, RtcpWriteError> {
        writer::check_padding(self.padding)?;

        let mut len = 0;
        for block in self.blocks.iter() {
            len += pad_to_4bytes(block.calculate_size()?);
        }

        Ok(Xr::MIN_PACKET_LEN - 4 + len)
    }

    /// Write this Xr packet data into `buf` without any validity checks.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Panic
    ///
    /// Panics if the buf is not large enough.
    #[inline]
    fn write_into_unchecked(&self, buf: &mut [u8]) -> usize {
        let mut idx = writer::write_header_unchecked::<Xr>(self.padding, 0, buf);
        buf[idx..idx + 4].copy_from_slice(&self.sender_ssrc.to_be_bytes());
        idx += 4;

        for block in self.blocks.iter() {
            let len = block.write_into_unchecked(&mut buf[idx..]);
            let padded_len = pad_to_4bytes(len);
            if len != padded_len {
                buf[len..padded_len].fill(0);
            }
            idx += padded_len;
        }
        idx
    }

    fn get_padding(&self) -> Option<u8> {
        if self.padding == 0 {
            return None;
        }

        Some(self.padding)
    }
}

/// The common header of an XR report block
#[derive(Debug)]
pub struct XrBlock<'a> {
    pub(crate) data: &'a [u8],
}

impl<'a> XrBlock<'a> {
    /// Parse this [`XrBlock`] into a specific implementation.
    pub fn parse_into<T: XrBlockParser<'a> + XrBlockStaticType>(
        &self,
    ) -> Result<T, RtcpParseError> {
        if T::BLOCK_TYPE != self.block_type() {
            return Err(RtcpParseError::WrongImplementation);
        }
        T::parse(self.data)
    }
}

impl<'a> XrBlockParser<'a> for XrBlock<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        if data.len() < 4 {
            return Err(RtcpParseError::Truncated {
                expected: 4,
                actual: data.len(),
            });
        }
        let ret = Self { data };
        if data.len() < ret.length() {
            return Err(RtcpParseError::Truncated {
                expected: ret.length(),
                actual: data.len(),
            });
        }

        Ok(ret)
    }

    #[inline(always)]
    fn header_data(&self) -> [u8; 4] {
        self.data[..4].try_into().unwrap()
    }
}

/// Trait for parsing XR report block data in [`Xr`] packets
///
/// Implementers only need to return the 4 byte RTCP header
/// from [`XrBlockParser::header_data`] to be able to use
/// the getters for the common RTCP packet fields.
pub trait XrBlockParser<'a>: Sized {
    /// Parse the provided XR block
    fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError>;

    /// Returns the common header for this XR Block.
    fn header_data(&self) -> [u8; 4];
}

pub trait XrBlockParserExt<'a>: XrBlockParser<'a> {
    /// The indicator for the particular XR block being parsed
    fn block_type(&self) -> u8 {
        self.header_data()[0]
    }

    /// The type specific value in the XR block header
    fn type_specific_byte(&self) -> u8 {
        self.header_data()[1]
    }

    /// The length (in bytes) of the XR block
    fn length(&self) -> usize {
        (u16_from_be_bytes(&self.header_data()[2..4]) as usize + 1) * 4
    }
}

impl<'a, T: XrBlockParser<'a>> XrBlockParserExt<'a> for T {}

/// A trait for implementations that contain a compile-time constant of the block type.
pub trait XrBlockStaticType {
    /// The block type identifier within a XR packet.
    const BLOCK_TYPE: u8;
}

/// Trait for writing a particular XR block implementation with a [`XrBuilder`].
pub trait XrBlockBuilder<'a>: RtcpPacketWriter {
    /// The type specific byte to place in the XR block header
    fn type_specific_byte(&self) -> u8;
}

pub trait XrBlockBuilderExt<'a>: XrBlockBuilder<'a> {
    fn write_header_unchecked(&self, buf: &mut [u8], block_type: u8, block_word_len: u16) -> usize {
        buf[0] = block_type;
        buf[1] = self.type_specific_byte();
        buf[2..4].copy_from_slice(&block_word_len.to_be_bytes());
        4
    }
}

impl<'a, T: XrBlockBuilder<'a>> XrBlockBuilderExt<'a> for T {}

pub(crate) fn xr_offset_sequence(seq: u16, start: u16, end: u16, thinning: u8) -> Option<u16> {
    let seq = seq
        .wrapping_mul(2u16.pow(thinning as u32))
        .wrapping_add(start);
    if end <= start {
        if seq < start && seq >= end {
            None
        } else {
            Some(seq)
        }
    } else if seq >= end {
        None
    } else {
        Some(seq)
    }
}

#[cfg(test)]
mod tests {
    use duplicate_rle::DuplicateRle;
    use loss_rle::LossRle;

    use super::*;

    #[test]
    fn xr_block_build_single() {
        let loss = LossRle::builder()
            .ssrc(0x8642_1357)
            .begin(100)
            .end(200)
            .thinning(0)
            .add_chunk(rle::RleChunk::RunLength(100));
        let builder = Xr::builder().sender_ssrc(0x8642_1357).add_block(loss);
        let len = builder.calculate_size().unwrap();
        let mut buf = vec![0; len];
        builder.write_into_unchecked(&mut buf);
        println!("{buf:x?}");

        let xr = Xr::parse(&buf).unwrap();
        assert_eq!(xr.sender_ssrc(), 0x8642_1357);
        let mut it = xr.block_iter();
        let rle = it.next().unwrap().parse_into::<LossRle>().unwrap();
        assert_eq!(rle.thinning(), 0);
        assert_eq!(rle.begin(), 100);
        assert_eq!(rle.end(), 200);
    }

    #[test]
    fn xr_block_build_2block() {
        let loss = LossRle::builder()
            .ssrc(0x8642_1357)
            .begin(100)
            .end(200)
            .thinning(0)
            .add_chunk(rle::RleChunk::RunLength(100));
        let duplicate = DuplicateRle::builder()
            .ssrc(0x8642_1357)
            .begin(101)
            .end(202)
            .thinning(1)
            .add_chunk(rle::RleChunk::SkipLength(100));
        let builder = Xr::builder()
            .sender_ssrc(0x8642_1357)
            .add_block(loss)
            .add_block(duplicate);
        let len = builder.calculate_size().unwrap();
        let mut buf = vec![0; len];
        builder.write_into_unchecked(&mut buf);
        println!("{buf:x?}");

        let xr = Xr::parse(&buf).unwrap();
        assert_eq!(xr.sender_ssrc(), 0x8642_1357);
        let mut it = xr.block_iter();
        let rle = it.next().unwrap().parse_into::<LossRle>().unwrap();
        assert_eq!(rle.thinning(), 0);
        assert_eq!(rle.begin(), 100);
        assert_eq!(rle.end(), 200);
        let rle = it.next().unwrap().parse_into::<DuplicateRle>().unwrap();
        assert_eq!(rle.thinning(), 1);
        assert_eq!(rle.begin(), 101);
        assert_eq!(rle.end(), 202);
    }

    #[test]
    fn xr_block_parse_truncated_header() {
        let data = [1, 0, 0];
        assert!(matches!(
            XrBlock::parse(&data),
            Err(RtcpParseError::Truncated {
                expected: 4,
                actual: 3
            })
        ));
    }

    #[test]
    fn xr_block_parse_truncated_block() {
        let data = [1, 0, 0, 1, 4, 2, 3];
        assert!(matches!(
            XrBlock::parse(&data),
            Err(RtcpParseError::Truncated {
                expected: 8,
                actual: 7
            })
        ));
    }

    #[test]
    fn xr_offset_at_start() {
        for thinning in 0..15 {
            assert_eq!(xr_offset_sequence(0, 100, 200, thinning), Some(100));
            assert_eq!(
                xr_offset_sequence(0, u16::MAX - 100, 200, thinning),
                Some(u16::MAX - 100)
            );
        }
    }

    #[test]
    fn xr_offset_at_end() {
        assert_eq!(xr_offset_sequence(99, 100, 200, 0), Some(199));
        assert_eq!(xr_offset_sequence(100, 100, 200, 0), None);

        assert_eq!(xr_offset_sequence(99, u16::MAX - 49, 50, 0), Some(49));
        assert_eq!(xr_offset_sequence(100, u16::MAX - 49, 50, 0), None);
    }

    #[test]
    fn xr_offset_thinning() {
        assert_eq!(xr_offset_sequence(49, 100, 200, 1), Some(198));
        assert_eq!(xr_offset_sequence(50, 100, 200, 1), None);
        assert_eq!(xr_offset_sequence(24, 100, 200, 2), Some(196));
        assert_eq!(xr_offset_sequence(25, 100, 200, 2), None);

        assert_eq!(xr_offset_sequence(49, u16::MAX - 49, 50, 1), Some(48));
        assert_eq!(xr_offset_sequence(50, u16::MAX - 49, 50, 1), None);
        assert_eq!(xr_offset_sequence(24, u16::MAX - 49, 50, 2), Some(46));
        assert_eq!(xr_offset_sequence(25, u16::MAX - 49, 50, 2), None);
    }
}
