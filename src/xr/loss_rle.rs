// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::prelude::*;
use crate::xr::rle::{Rle, RleBuilder, RleChunk};
use crate::xr::{XrBlockBuilder, XrBlockParser};
use crate::{RtcpParseError, RtcpWriteError};

use super::XrBlockStaticType;

/// Run-Length-Encoded packet loss information as specified in RFC 3611
pub struct LossRle<'a> {
    rle: Rle<'a>,
}

impl<'a> XrBlockStaticType for LossRle<'a> {
    const BLOCK_TYPE: u8 = 0x1;
}

impl<'a> XrBlockParser<'a> for LossRle<'a> {
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

impl<'a> LossRle<'a> {
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

    /// An iterator over the sequence numbers in this [`LossRle`].
    pub fn sequence_iter(&self) -> impl Iterator<Item = u16> + '_ {
        self.rle.sequence_iter()
    }

    /// An iterator over the chunks in this [`LossRle`].
    ///
    /// This returns chunks as they are stored without any sequence number translation applied.
    /// i.e. each chunk starts from a sequence number of 0.
    pub fn chunk_iter(&self) -> impl Iterator<Item = RleChunk> + '_ {
        self.rle.chunk_iter()
    }

    /// Returns a [`LossRleBuilder`] for constructing a [`LossRle`] block.
    pub fn builder() -> LossRleBuilder {
        let mut builder = LossRleBuilder {
            rle: Rle::builder(),
        };
        builder.rle = builder.rle.block_type(Self::BLOCK_TYPE);
        builder
    }
}

#[derive(Debug, Default)]
pub struct LossRleBuilder {
    rle: RleBuilder,
}

impl LossRleBuilder {
    /// Set the SSRC the [`LossRle`] refers to.
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

    /// Set the thinning value for the [`LossRle`].
    ///
    /// Thinning signals that ever this block reports on every 2^thinning sequence number.
    pub fn thinning(mut self, thinning: u8) -> Self {
        assert!(thinning <= 0xf);
        self.rle = self.rle.thinning(thinning);
        self
    }

    /// Add a chunk for this [`LossRle`]
    pub fn add_chunk(mut self, chunk: RleChunk) -> Self {
        self.rle = self.rle.add_chunk(chunk);
        self
    }
}

impl<'a> XrBlockBuilder<'a> for LossRleBuilder {
    fn type_specific_byte(&self) -> u8 {
        self.rle.type_specific_byte()
    }
}

impl RtcpPacketWriter for LossRleBuilder {
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
    fn loss_rle_builder_simple() {
        let builder = LossRle::builder()
            .ssrc(0x1357_9864)
            .begin(400)
            .end(500)
            .thinning(1)
            .add_chunk(RleChunk::RunLength(50));
        let len = builder.calculate_size().unwrap();
        let mut buf = vec![0; len];
        builder.write_into_unchecked(&mut buf);
        println!("{buf:x?}");

        let rle = LossRle::parse(&buf).unwrap();
        assert_eq!(rle.media_ssrc(), 0x1357_9864);
        assert_eq!(rle.thinning(), 1);
        assert_eq!(rle.begin(), 400);
        assert_eq!(rle.end(), 500);
        let expected = (400..500).filter(|x| x % 2 == 0).collect::<Vec<_>>();
        let sequence = rle.sequence_iter().collect::<Vec<_>>();
        assert_eq!(sequence, expected);
    }
}
