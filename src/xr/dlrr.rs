// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::prelude::*;
use crate::utils::u32_from_be_bytes;
use crate::xr::{XrBlockBuilder, XrBlockParser, XrBlockStaticType};
use crate::{RtcpParseError, RtcpWriteError};

use super::XrBlock;

/// Packet Receipt Times information as specified in RFC 3611
#[derive(Debug)]
pub struct DelaySinceLastReceiverReport<'a> {
    block: XrBlock<'a>,
}

impl<'a> XrBlockStaticType for DelaySinceLastReceiverReport<'a> {
    const BLOCK_TYPE: u8 = 0x5;
}

impl<'a> XrBlockParser<'a> for DelaySinceLastReceiverReport<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        let block = XrBlock::parse(data)?;
        if data.len() < 16 {
            return Err(RtcpParseError::Truncated {
                expected: 16,
                actual: data.len(),
            });
        }
        let ret = Self { block };
        if ret.length() % 16 != 0 {
            return Err(RtcpParseError::Truncated {
                expected: ret.length() + ret.length() % 16,
                actual: data.len(),
            });
        }
        Ok(ret)
    }

    #[inline(always)]
    fn header_data(&self) -> [u8; 4] {
        self.block.data[..4].try_into().unwrap()
    }
}

impl<'a> DelaySinceLastReceiverReport<'a> {
    /// An iterator over the report blocks [`DelaySinceLastReceiverReport`].
    pub fn block_iter(&self) -> impl Iterator<Item = DelaySinceLastReceiverReportBlock> + '_ {
        DelaySinceLastReceiverReportBlockIter {
            dlrr: self,
            data_offset: 4,
        }
    }

    /// Returns a [`DelaySinceLastReceiverReportBuilder`] for constructing a
    /// [`DelaySinceLastReceiverReport`] block.
    pub fn builder() -> DelaySinceLastReceiverReportBuilder {
        DelaySinceLastReceiverReportBuilder::default()
    }
}

#[derive(Debug, Default)]
pub struct DelaySinceLastReceiverReportBlock {
    ssrc: u32,
    last_receiver_report: u32,
    delay_since_last_receiver_report_timestamp: u32,
}

impl DelaySinceLastReceiverReportBlock {
    fn parse(data: &[u8]) -> Self {
        Self {
            ssrc: u32_from_be_bytes(&data[..4]),
            last_receiver_report: u32_from_be_bytes(&data[4..8]),
            delay_since_last_receiver_report_timestamp: u32_from_be_bytes(&data[8..12]),
        }
    }

    /// The SSRC this block refers to
    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// The NTP 16.16 fixed point time that a receiver report was last received
    pub fn last_receiver_report(&self) -> u32 {
        self.last_receiver_report
    }

    /// 16.16 fixed point duration since the last receiver report was received
    pub fn delay_since_last_receiver_report_timestamp(&self) -> u32 {
        self.delay_since_last_receiver_report_timestamp
    }

    pub fn builder() -> DelaySinceLastReceiverReportBlockBuilder {
        DelaySinceLastReceiverReportBlockBuilder::default()
    }
}

#[derive(Debug, Default)]
pub struct DelaySinceLastReceiverReportBlockBuilder {
    dlrr: DelaySinceLastReceiverReportBlock,
}

impl DelaySinceLastReceiverReportBlockBuilder {
    /// The SSRC this block refers to
    pub fn ssrc(mut self, ssrc: u32) -> Self {
        self.dlrr.ssrc = ssrc;
        self
    }

    /// The NTP 16.16 fixed point time that a receiver report was last received
    pub fn last_receiver_report(mut self, last_receiver_report: u32) -> Self {
        self.dlrr.last_receiver_report = last_receiver_report;
        self
    }

    /// 16.16 fixed point duration since the last receiver report was received
    pub fn delay_since_last_receiver_report_timestamp(
        mut self,
        delay_since_last_receiver_report_timestamp: u32,
    ) -> Self {
        self.dlrr.delay_since_last_receiver_report_timestamp =
            delay_since_last_receiver_report_timestamp;
        self
    }

    fn write_into(&self, buf: &mut [u8]) {
        buf[..4].copy_from_slice(&self.dlrr.ssrc.to_be_bytes());
        buf[4..8].copy_from_slice(&self.dlrr.last_receiver_report.to_be_bytes());
        buf[8..12].copy_from_slice(
            &self
                .dlrr
                .delay_since_last_receiver_report_timestamp
                .to_be_bytes(),
        );
    }
}

#[derive(Debug)]
struct DelaySinceLastReceiverReportBlockIter<'a> {
    dlrr: &'a DelaySinceLastReceiverReport<'a>,
    data_offset: usize,
}

impl<'a> Iterator for DelaySinceLastReceiverReportBlockIter<'a> {
    type Item = DelaySinceLastReceiverReportBlock;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data_offset + 12 > self.dlrr.block.data.len() {
            return None;
        }
        let block =
            DelaySinceLastReceiverReportBlock::parse(&self.dlrr.block.data[self.data_offset..]);
        self.data_offset += 12;
        Some(block)
    }
}

/// A builder for a [`DelaySinceLastReceiverReport`]
#[derive(Debug, Default)]
pub struct DelaySinceLastReceiverReportBuilder {
    blocks: Vec<DelaySinceLastReceiverReportBlockBuilder>,
}

impl DelaySinceLastReceiverReportBuilder {
    /// Add a report block to this [`DelaySinceLastReceiverReport`]
    pub fn add_block(mut self, block: DelaySinceLastReceiverReportBlockBuilder) -> Self {
        self.blocks.push(block);
        self
    }
}

impl<'a> XrBlockBuilder<'a> for DelaySinceLastReceiverReportBuilder {
    fn type_specific_byte(&self) -> u8 {
        0
    }
}

impl RtcpPacketWriter for DelaySinceLastReceiverReportBuilder {
    fn calculate_size(&self) -> Result<usize, RtcpWriteError> {
        Ok(4 + self.blocks.len() * 12)
    }

    fn write_into_unchecked(&self, buf: &mut [u8]) -> usize {
        let mut idx = self.write_header_unchecked(
            buf,
            DelaySinceLastReceiverReport::BLOCK_TYPE,
            (self.blocks.len() * 12 / 4) as u16,
        );
        for block in self.blocks.iter() {
            block.write_into(&mut buf[idx..]);
            idx += 12;
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
    fn dlrr_single_block() {
        let builder = DelaySinceLastReceiverReport::builder().add_block(
            DelaySinceLastReceiverReportBlock::builder()
                .ssrc(0x9876_5432)
                .last_receiver_report(0x1357_8642)
                .delay_since_last_receiver_report_timestamp(0x8642_1357),
        );
        let len = builder.calculate_size().unwrap();
        let mut buf = vec![0; len];
        builder.write_into(&mut buf).unwrap();
        println!("{buf:x?}");

        let dlrr = DelaySinceLastReceiverReport::parse(&buf).unwrap();
        let mut block_iter = dlrr.block_iter();
        let block = block_iter.next().unwrap();
        assert!(block_iter.next().is_none());
        assert_eq!(block.ssrc(), 0x9876_5432);
        assert_eq!(block.last_receiver_report(), 0x1357_8642);
        assert_eq!(
            block.delay_since_last_receiver_report_timestamp(),
            0x8642_1357
        );
    }
}
