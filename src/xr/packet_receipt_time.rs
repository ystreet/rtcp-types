// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::prelude::*;
use crate::utils::u32_from_be_bytes;
use crate::xr::{XrBlock, XrBlockBuilder, XrBlockParser, XrBlockStaticType};
use crate::{RtcpParseError, RtcpWriteError};

use super::{u16_from_be_bytes, xr_offset_sequence};

/// Packet Receipt Times information as specified in RFC 3611
#[derive(Debug)]
pub struct PacketReceiptTimes<'a> {
    block: XrBlock<'a>,
}

impl XrBlockStaticType for PacketReceiptTimes<'_> {
    const BLOCK_TYPE: u8 = 0x3;
}

impl<'a> XrBlockParser<'a> for PacketReceiptTimes<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        let block = XrBlock::parse(data)?;
        let ret = Self { block };
        Ok(ret)
    }

    #[inline(always)]
    fn header_data(&self) -> [u8; 4] {
        self.block.data[..4].try_into().unwrap()
    }
}

impl PacketReceiptTimes<'_> {
    /// The amount of thinning applied to the sequence number space. Every 2^thinning sequence
    /// number has been reported
    pub fn thinning(&self) -> u8 {
        self.block.type_specific_byte() & 0x0f
    }

    /// The SSRC of the media being reported on
    pub fn media_ssrc(&self) -> u32 {
        u32_from_be_bytes(&self.block.data[4..8])
    }

    /// This is the (inclusive) start of the sequence number range being reported in this Rle block.
    /// This start value is included in the range.
    pub fn begin(&self) -> u16 {
        u16_from_be_bytes(&self.block.data[8..10])
    }

    /// This is the (exclusive) end of the sequence number range being reported in this Rle block.
    /// This end value is not included in the range.
    pub fn end(&self) -> u16 {
        u16_from_be_bytes(&self.block.data[10..12])
    }

    /// An iterator over the sequence numbers in this [`PacketReceiptTimes`].
    pub fn sequence_iter(&self) -> impl Iterator<Item = (u16, u32)> + '_ {
        PacketReceiptTimesIter {
            prt: self,
            data_offset: 12,
        }
    }

    /// Returns a [`PacketReceiptTimesBuilder`] for constructing a [`PacketReceiptTimes`] block.
    pub fn builder() -> PacketReceiptTimesBuilder {
        PacketReceiptTimesBuilder::default()
    }
}

#[derive(Debug)]
struct PacketReceiptTimesIter<'a> {
    prt: &'a PacketReceiptTimes<'a>,
    data_offset: usize,
}

impl Iterator for PacketReceiptTimesIter<'_> {
    type Item = (u16, u32);

    fn next(&mut self) -> Option<Self::Item> {
        if self.data_offset >= self.prt.block.data.len() {
            return None;
        }
        let ts = u32_from_be_bytes(&self.prt.block.data[self.data_offset..self.data_offset + 4]);
        self.data_offset += 4;
        xr_offset_sequence(
            (self.data_offset / 4 - 4) as u16,
            self.prt.begin(),
            self.prt.end(),
            self.prt.thinning(),
        )
        .map(|seq| (seq, ts))
    }
}

/// A builder for a [`PacketReceiptTimes`]
#[derive(Debug, Default)]
pub struct PacketReceiptTimesBuilder {
    media_ssrc: u32,
    begin: u16,
    end: u16,
    thinning: u8,
    receipt_times: Vec<u32>,
}

impl PacketReceiptTimesBuilder {
    /// Set the SSRC the [`PacketReceiptTimesBuilder`] refers to.
    pub fn ssrc(mut self, ssrc: u32) -> Self {
        self.media_ssrc = ssrc;
        self
    }

    /// Set the start of the sequence number range.
    pub fn begin(mut self, begin: u16) -> Self {
        self.begin = begin;
        self
    }

    /// Set the end of the sequence number range.
    pub fn end(mut self, end: u16) -> Self {
        self.end = end;
        self
    }

    /// Set the thinning value for the [`PacketReceiptTimes`].
    ///
    /// Thinning signals that ever this block reports on every 2^thinning sequence number.
    pub fn thinning(mut self, thinning: u8) -> Self {
        assert!(thinning <= 0xf);
        self.thinning = thinning;
        self
    }

    /// Add a receipt time to this [`PacketReceiptTimes`]
    pub fn add_time(mut self, time: u32) -> Self {
        self.receipt_times.push(time);
        self
    }
}

impl XrBlockBuilder<'_> for PacketReceiptTimesBuilder {
    fn type_specific_byte(&self) -> u8 {
        self.thinning
    }
}

impl RtcpPacketWriter for PacketReceiptTimesBuilder {
    fn calculate_size(&self) -> Result<usize, RtcpWriteError> {
        Ok(12 + self.receipt_times.len() * 4)
    }

    fn write_into_unchecked(&self, buf: &mut [u8]) -> usize {
        buf[0] = PacketReceiptTimes::BLOCK_TYPE;
        buf[1] = self.thinning & 0xf;
        buf[2..4].copy_from_slice(&(self.receipt_times.len() as u16 + 2).to_be_bytes());
        buf[4..8].copy_from_slice(&self.media_ssrc.to_be_bytes());
        buf[8..10].copy_from_slice(&self.begin.to_be_bytes());
        buf[10..12].copy_from_slice(&self.end.to_be_bytes());
        let mut idx = 12;
        for time in self.receipt_times.iter() {
            buf[idx..idx + 4].copy_from_slice(&time.to_be_bytes());
            idx += 4;
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
    fn receipt_times_no_thinning() {
        let mut builder = PacketReceiptTimes::builder()
            .ssrc(0x9876_5432)
            .begin(400)
            .end(410)
            .thinning(0);
        for i in 0..10 {
            builder = builder.add_time(i * 7);
        }
        let len = builder.calculate_size().unwrap();
        let mut buf = vec![0; len];
        builder.write_into(&mut buf).unwrap();

        let prt = PacketReceiptTimes::parse(&buf).unwrap();
        assert_eq!(prt.media_ssrc(), 0x9876_5432);
        assert_eq!(prt.thinning(), 0);
        assert_eq!(prt.begin(), 400);
        assert_eq!(prt.end(), 410);
        let mut seq_iter = prt.sequence_iter();
        for i in 0..10 {
            assert_eq!(seq_iter.next().unwrap(), (400 + i as u16, i * 7));
        }
    }
}
