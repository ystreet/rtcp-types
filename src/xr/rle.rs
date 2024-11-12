// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::prelude::*;
use crate::{utils::u32_from_be_bytes, RtcpParseError};

use super::{pad_to_4bytes, u16_from_be_bytes, xr_offset_sequence, RtcpPacketWriter, XrBlock};

/// Run-Length-Encoded block (packet loss or duplicate) as specified in RFC 3611
#[derive(Debug)]
pub struct Rle<'a> {
    pub(crate) block: XrBlock<'a>,
}

impl<'a> Rle<'a> {
    /// Parse a Rle from a sequence of byte
    pub fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        let block = XrBlock::parse(data)?;
        if block.length() < 12 {
            return Err(RtcpParseError::Truncated {
                expected: 12,
                actual: block.length(),
            });
        }
        let ret = Self { block };
        Ok(ret)
    }

    /// The amount of thinning applied to the sequence number space. Every 2^thinning sequence
    /// number has been reported
    pub fn thinning(&self) -> u8 {
        self.block.data[1] & 0x0f
    }

    /// The SSRC of the media being reported on
    pub fn media_ssrc(&self) -> u32 {
        u32_from_be_bytes(&self.block.data[4..8])
    }

    /// This is the (inclusive) start of the sequence number range being reported in this Rle packet.
    /// This start value is included in the range.
    pub fn begin(&self) -> u16 {
        u16_from_be_bytes(&self.block.data[8..10])
    }

    /// This is the (exclusive) end of the sequence number range being reported in this Rle packet.
    /// This end value is not included in the range.
    pub fn end(&self) -> u16 {
        u16_from_be_bytes(&self.block.data[10..12])
    }

    /// An iterator over the sequence numbers in this [`Rle`]
    pub fn sequence_iter(&self) -> impl Iterator<Item = u16> + '_ {
        RleSequenceIter {
            rle: self,
            block_iter: RleBlockIter {
                rle: self,
                block_offset: 12,
            },
            chunk_iter: None,
            seq_offset: self.begin(),
        }
    }

    /// An iterator over the chunks in this [`Rle`]
    pub fn chunk_iter(&self) -> impl Iterator<Item = RleChunk> + '_ {
        RleBlockIter {
            rle: self,
            block_offset: 12,
        }
    }

    /// Returns a new [`RleBuilder`] for constructing a [`Rle`] block.
    pub fn builder() -> RleBuilder {
        RleBuilder::default()
    }
}

#[derive(Debug)]
struct RleBlockIter<'a> {
    rle: &'a Rle<'a>,
    // which chunk we are looking at
    block_offset: usize,
}

impl<'a> Iterator for RleBlockIter<'a> {
    type Item = RleChunk;

    fn next(&mut self) -> Option<Self::Item> {
        if self.block_offset + 2 >= self.rle.block.length() {
            return None;
        }
        let chunk = RleChunk::parse(&self.rle.block.data[self.block_offset..self.block_offset + 2]);
        self.block_offset += 2;
        Some(chunk)
    }
}

pub struct RleSequenceIter<'a> {
    rle: &'a Rle<'a>,
    block_iter: RleBlockIter<'a>,
    chunk_iter: Option<RleChunkIter>,
    seq_offset: u16,
}

impl<'a> Iterator for RleSequenceIter<'a> {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(it) = self.chunk_iter.as_mut() {
                let ret = it.next();
                if ret.is_none() {
                    let len = it.length() as u16;
                    let diff = 2u16.pow(self.rle.thinning() as u32).wrapping_mul(len);
                    self.seq_offset = self.seq_offset.wrapping_add(diff);
                    self.chunk_iter = None;
                } else {
                    return ret.and_then(|seq| {
                        xr_offset_sequence(
                            seq,
                            self.seq_offset,
                            self.rle.end(),
                            self.rle.thinning(),
                        )
                    });
                }
            }
            let chunk = self.block_iter.next()?;
            self.chunk_iter = Some(chunk.iter());
        }
    }
}

/// The various options for what a RLE chunk can be.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RleChunk {
    /// Run length where 1s are set. The least significant 14 bits contain the length of the run.
    RunLength(u16),
    /// Run length where 0s are set. The least significant 14 bits contain the length of the run.
    SkipLength(u16),
    /// The least significant 15 bits contain a bit mask of values. The value is read from most
    /// significat to the least significant bit.
    BitVector(u16),
    /// Null value.  Should be skipped in most scenarios.
    Null,
}

impl RleChunk {
    fn parse(data: &[u8]) -> Self {
        let value = u16_from_be_bytes(data);
        if value == 0 {
            return Self::Null;
        }
        if (value & 0x8000) == 0x8000 {
            Self::BitVector(value & !0x8000)
        } else if (value & 0x4000) == 0x4000 {
            Self::RunLength(value & !0xc000)
        } else {
            Self::SkipLength(value & !0xc000)
        }
    }

    fn length(&self) -> usize {
        match self {
            Self::Null => 0,
            Self::BitVector(_) => 15,
            Self::SkipLength(rle) | Self::RunLength(rle) => (rle & !0xc000) as usize,
        }
    }

    fn iter(&self) -> RleChunkIter {
        RleChunkIter {
            chunk: *self,
            chunk_offset: 0,
        }
    }

    fn write_into(&self, buf: &mut [u8]) {
        match self {
            Self::Null => {
                buf[0] = 0x0;
                buf[1] = 0x0;
            }
            Self::RunLength(rle) => {
                buf[..2].copy_from_slice(&((rle & !0xc000) | 0x4000).to_be_bytes())
            }
            Self::SkipLength(rle) => buf[..2].copy_from_slice(&(rle & !0xc000).to_be_bytes()),
            Self::BitVector(vector) => buf[..2].copy_from_slice(&(vector | 0x8000).to_be_bytes()),
        }
    }
}

#[derive(Debug)]
struct RleChunkIter {
    chunk: RleChunk,
    chunk_offset: u16,
}

impl Iterator for RleChunkIter {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        match self.chunk {
            RleChunk::Null | RleChunk::SkipLength(_) => None,
            RleChunk::BitVector(vector) => {
                while self.chunk_offset < 15 {
                    let value = (vector & !0x8000) >> (14 - self.chunk_offset) & 0x1;
                    if value > 0 {
                        break;
                    }
                    self.chunk_offset += 1
                }
                if self.chunk_offset >= 15 {
                    None
                } else {
                    let ret = self.chunk_offset;
                    self.chunk_offset += 1;
                    Some(ret)
                }
            }
            RleChunk::RunLength(rlen) => {
                let rlen = rlen & !0xc000;
                if self.chunk_offset < rlen {
                    let ret = self.chunk_offset;
                    self.chunk_offset += 1;
                    Some(ret)
                } else {
                    None
                }
            }
        }
    }
}

impl RleChunkIter {
    fn length(&self) -> usize {
        self.chunk.length()
    }
}

#[derive(Debug, Default)]
pub struct RleBuilder {
    block_type: u8,
    media_ssrc: u32,
    begin: u16,
    end: u16,
    chunks: Vec<RleChunk>,
    thinning: u8,
}

impl RleBuilder {
    pub fn block_type(mut self, block_type: u8) -> Self {
        self.block_type = block_type;
        self
    }

    pub fn ssrc(mut self, ssrc: u32) -> Self {
        self.media_ssrc = ssrc;
        self
    }

    pub fn begin(mut self, begin: u16) -> Self {
        self.begin = begin;
        self
    }

    pub fn end(mut self, end: u16) -> Self {
        self.end = end;
        self
    }

    pub fn thinning(mut self, thinning: u8) -> Self {
        self.thinning = thinning;
        self
    }

    pub fn add_chunk(mut self, chunk: RleChunk) -> Self {
        self.chunks.push(chunk);
        self
    }
}

impl<'a> XrBlockBuilder<'a> for RleBuilder {
    fn type_specific_byte(&self) -> u8 {
        self.thinning & 0xf
    }
}

impl RtcpPacketWriter for RleBuilder {
    fn calculate_size(&self) -> Result<usize, crate::RtcpWriteError> {
        Ok(12 + pad_to_4bytes(self.chunks.len() * 2))
    }

    fn write_into_unchecked(&self, buf: &mut [u8]) -> usize {
        self.write_header_unchecked(
            buf,
            self.block_type,
            (pad_to_4bytes(self.chunks.len() * 2) / 4) as u16 + 2,
        );
        buf[4..8].copy_from_slice(&self.media_ssrc.to_be_bytes());
        buf[8..10].copy_from_slice(&self.begin.to_be_bytes());
        buf[10..12].copy_from_slice(&self.end.to_be_bytes());
        let mut idx = 12;
        for chunk in self.chunks.iter() {
            chunk.write_into(&mut buf[idx..idx + 2]);
            idx += 2;
        }
        if idx % 4 != 0 {
            RleChunk::Null.write_into(&mut buf[idx..idx + 2]);
            idx += 2;
        }
        idx
    }

    fn get_padding(&self) -> Option<u8> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_chunk_iter() {
        let chunk = RleChunk::BitVector(0b1011_0100_0111_1001);
        assert_eq!(chunk.length(), 15);
        let sequences = chunk.iter().collect::<Vec<_>>();
        let expected = vec![1, 2, 4, 8, 9, 10, 11, 14];
        assert_eq!(sequences, expected);
    }

    #[test]
    fn bit_chunk_iter_single_value() {
        for i in 0..14 {
            let chunk = RleChunk::BitVector(0x8000 | (0x1 << i));
            assert_eq!(chunk.length(), 15);
            let sequences = chunk.iter().collect::<Vec<_>>();
            let expected = vec![14 - i];
            assert_eq!(sequences, expected);
        }
    }

    #[test]
    fn null_chunk_iter() {
        let chunk = RleChunk::Null;
        assert_eq!(chunk.length(), 0);
        assert_eq!(chunk.iter().next(), None);
    }

    #[test]
    fn skip_chunk_iter() {
        let chunk = RleChunk::SkipLength(29);
        assert_eq!(chunk.length(), 29);
        assert_eq!(chunk.iter().next(), None);
    }

    #[test]
    fn run_chunk_iter() {
        let chunk = RleChunk::RunLength(18);
        assert_eq!(chunk.length(), 18);
        let expected = (0..18).collect::<Vec<_>>();
        let sequences = chunk.iter().collect::<Vec<_>>();
        assert_eq!(sequences, expected);
    }

    #[test]
    fn rle_builder_vector_larger_than_sequence_range() {
        let builder = Rle::builder()
            .block_type(0x48)
            .ssrc(0x1357_9864)
            .begin(u16::MAX - 3)
            .end(4)
            .thinning(0)
            .add_chunk(RleChunk::BitVector(0b0111_1111_1111_1111));
        let len = builder.calculate_size().unwrap();
        let mut buf = vec![0; len];
        builder.write_into_unchecked(&mut buf);
        println!("{buf:x?}");

        let rle = Rle::parse(&buf).unwrap();
        assert_eq!(rle.media_ssrc(), 0x1357_9864);
        assert_eq!(rle.thinning(), 0);
        assert_eq!(rle.begin(), u16::MAX - 3);
        assert_eq!(rle.end(), 4);
        let expected = (u16::MAX - 3..=u16::MAX).chain(0..4).collect::<Vec<_>>();
        let sequence = rle.sequence_iter().collect::<Vec<_>>();
        assert_eq!(sequence, expected);
    }
}
