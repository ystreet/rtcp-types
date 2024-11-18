// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::prelude::*;
use crate::xr::rle::{Rle, RleBuilder, RleChunk};
use crate::xr::{XrBlockBuilder, XrBlockParser, XrBlockStaticType};
use crate::{RtcpParseError, RtcpWriteError};

/// Run-Length-Encoded packet duplicate information as specified in RFC 3611
#[derive(Debug)]
pub struct DuplicateRle<'a> {
    rle: Rle<'a>,
}

impl<'a> XrBlockStaticType for DuplicateRle<'a> {
    const BLOCK_TYPE: u8 = 0x2;
}

impl<'a> XrBlockParser<'a> for DuplicateRle<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        let rle = Rle::parse(data)?;
        let ret = Self { rle };
        Ok(ret)
    }

    #[inline(always)]
    fn header_data(&self) -> [u8; 4] {
        self.rle.block.header_data()
    }
}

impl<'a> DuplicateRle<'a> {
    /// The amount of thinning applied to the sequence number space. Every 2^thinning sequence
    /// number has been reported
    pub fn thinning(&self) -> u8 {
        self.rle.thinning()
    }

    /// The SSRC of the media being reported on
    pub fn media_ssrc(&self) -> u32 {
        self.rle.media_ssrc()
    }

    /// This is the (inclusive) start of the sequence number range being reported in this Rle block.
    /// This start value is included in the range.
    pub fn begin(&self) -> u16 {
        self.rle.begin()
    }

    /// This is the (exclusive) end of the sequence number range being reported in this Rle block.
    /// This end value is not included in the range.
    pub fn end(&self) -> u16 {
        self.rle.end()
    }

    /// An iterator over the sequence numbers in this [`DuplicateRle`].
    pub fn sequence_iter(&self) -> impl Iterator<Item = u16> + '_ {
        self.rle.sequence_iter()
    }

    /// An iterator over the chunks in this [`DuplicateRle`].
    ///
    /// This returns chunks as they are stored without any sequence number translation applied.
    /// i.e. each chunk starts from a sequence number of 0.
    pub fn chunk_iter(&self) -> impl Iterator<Item = RleChunk> + '_ {
        self.rle.chunk_iter()
    }

    /// Returns a [`DuplicateRleBuilder`] for constructing a [`DuplicateRle`] block.
    pub fn builder() -> DuplicateRleBuilder {
        let mut builder = DuplicateRleBuilder {
            rle: Rle::builder(),
        };
        builder.rle = builder.rle.block_type(Self::BLOCK_TYPE);
        builder
    }
}

/// Builder for a [`DuplicateRle`]
#[derive(Debug, Default)]
pub struct DuplicateRleBuilder {
    rle: RleBuilder,
}

impl DuplicateRleBuilder {
    /// Set the SSRC the [`DuplicateRle`] refers to.
    pub fn ssrc(mut self, ssrc: u32) -> Self {
        self.rle = self.rle.ssrc(ssrc);
        self
    }

    /// Set the start of the sequence number range.
    pub fn begin(mut self, begin: u16) -> Self {
        self.rle = self.rle.begin(begin);
        self
    }

    /// Set the end of the sequence number range.
    pub fn end(mut self, end: u16) -> Self {
        self.rle = self.rle.end(end);
        self
    }

    /// Set the thinning value for the [`DuplicateRle`].
    ///
    /// Thinning signals that ever this block reports on every 2^thinning sequence number.
    pub fn thinning(mut self, thinning: u8) -> Self {
        assert!(thinning <= 0xf);
        self.rle = self.rle.thinning(thinning);
        self
    }

    /// Add a chunk for this [`DuplicateRle`]
    pub fn add_chunk(mut self, chunk: RleChunk) -> Self {
        self.rle = self.rle.add_chunk(chunk);
        self
    }
}

impl<'a> XrBlockBuilder<'a> for DuplicateRleBuilder {
    fn type_specific_byte(&self) -> u8 {
        self.rle.type_specific_byte()
    }
}

impl RtcpPacketWriter for DuplicateRleBuilder {
    fn calculate_size(&self) -> Result<usize, RtcpWriteError> {
        self.rle.calculate_size()
    }

    fn write_into_unchecked(&self, buf: &mut [u8]) -> usize {
        self.rle.write_into_unchecked(buf)
    }

    fn get_padding(&self) -> Option<u8> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_rle_builder_wraparound() {
        let builder = DuplicateRle::builder()
            .ssrc(0x1357_9864)
            .begin(u16::MAX - 51)
            .end(50)
            .thinning(1)
            .add_chunk(RleChunk::RunLength(51));
        let len = builder.calculate_size().unwrap();
        let mut buf = vec![0; len];
        builder.write_into_unchecked(&mut buf);
        println!("{buf:x?}");

        let rle = DuplicateRle::parse(&buf).unwrap();
        assert_eq!(rle.media_ssrc(), 0x1357_9864);
        assert_eq!(rle.thinning(), 1);
        assert_eq!(rle.begin(), u16::MAX - 51);
        assert_eq!(rle.end(), 50);
        let expected = (u16::MAX - 51..u16::MAX)
            .chain(0..50)
            .filter(|x| x % 2 == 0)
            .collect::<Vec<_>>();
        let sequence = rle.sequence_iter().collect::<Vec<_>>();
        assert_eq!(sequence, expected);
    }
}
