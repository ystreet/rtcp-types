// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    utils::{parser::*, writer::*},
    ReportBlock, ReportBlockBuilder, RtcpPacket, RtcpParseError, RtcpWriteError,
};

/// A Parsed Receiver Report packet.
#[derive(Debug, PartialEq, Eq)]
pub struct ReceiverReport<'a> {
    data: &'a [u8],
}

impl<'a> RtcpPacket for ReceiverReport<'a> {
    const MIN_PACKET_LEN: usize = 8;
    const PACKET_TYPE: u8 = 201;
}

impl<'a> ReceiverReport<'a> {
    const MAX_REPORTS: u8 = Self::MAX_COUNT;

    pub fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        check_packet::<Self>(data)?;

        let req_len =
            Self::MIN_PACKET_LEN + parse_count(data) as usize * ReportBlock::EXPECTED_SIZE;
        if req_len < data.len() {
            return Err(RtcpParseError::Truncated {
                expected: req_len,
                actual: data.len(),
            });
        }

        Ok(Self { data })
    }

    pub fn version(&self) -> u8 {
        parse_version(self.data)
    }

    pub fn padding(&self) -> Option<u8> {
        parse_padding(self.data)
    }

    pub fn n_reports(&self) -> u8 {
        parse_count(self.data)
    }

    pub fn length(&self) -> usize {
        parse_length(self.data)
    }

    pub fn ssrc(&self) -> u32 {
        parse_ssrc(self.data)
    }

    pub fn report_blocks(&self) -> impl Iterator<Item = ReportBlock<'a>> + '_ {
        self.data[8..8 + (self.n_reports() as usize * 24)]
            .chunks_exact(24)
            .map(|b| ReportBlock::parse(b).unwrap())
    }

    pub fn builder(ssrc: u32) -> ReceiverReportBuilder {
        ReceiverReportBuilder::new(ssrc)
    }
}

/// Receiver Report Builder
#[derive(Debug)]
pub struct ReceiverReportBuilder {
    ssrc: u32,
    padding: u8,
    report_blocks: Vec<ReportBlockBuilder>,
}

impl ReceiverReportBuilder {
    fn new(ssrc: u32) -> Self {
        ReceiverReportBuilder {
            ssrc,
            padding: 0,
            report_blocks: Vec::with_capacity(ReceiverReport::MAX_REPORTS as usize),
        }
    }

    /// Sets the number of padding bytes to use for this receiver report.
    pub fn padding(mut self, padding: u8) -> Self {
        self.padding = padding;
        self
    }

    pub fn get_padding(&self) -> u8 {
        self.padding
    }

    /// Adds the provided Report Block.
    pub fn add_report_block(mut self, report_block: ReportBlockBuilder) -> Self {
        self.report_blocks.push(report_block);
        self
    }

    /// Calculates the size required to write this Receiver Report packet.
    ///
    /// Returns an error if:
    ///
    /// * Too many Report Blocks where added.
    /// * A Report Block is erroneous.
    /// * The padding is not a multiple of 4.
    pub fn calculate_size(&self) -> Result<usize, RtcpWriteError> {
        if self.report_blocks.len() > ReceiverReport::MAX_REPORTS as usize {
            return Err(RtcpWriteError::TooManyReportBlocks {
                count: self.report_blocks.len(),
                max: ReceiverReport::MAX_REPORTS,
            });
        }

        check_padding(self.padding)?;

        let mut report_blocks_size = 0;
        for rb in self.report_blocks.iter() {
            report_blocks_size += rb.calculate_size()?;
        }

        Ok(ReceiverReport::MIN_PACKET_LEN + report_blocks_size + self.padding as usize)
    }

    /// Writes this Receiver Report into `buf` without any validity checks.
    ///
    /// Uses the length of the buffer for the length field.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Panic
    ///
    /// Panics if the buf is not large enough.
    pub(crate) fn write_into_unchecked(&self, buf: &mut [u8]) -> usize {
        write_header_unchecked::<ReceiverReport>(self.padding, self.report_blocks.len() as u8, buf);

        buf[4..8].copy_from_slice(&self.ssrc.to_be_bytes());

        let mut idx = 8;
        let mut end = idx;
        for report_block in self.report_blocks.iter() {
            end += ReportBlock::EXPECTED_SIZE;
            report_block.write_into_unchecked(&mut buf[idx..end]);
            idx = end;
        }

        end += write_padding_unchecked(self.padding, &mut buf[idx..]);

        end
    }

    /// Writes this Receiver Report into `buf`.
    ///
    /// Returns an error if:
    ///
    /// * The buffer is too small.
    /// * Too many Report Blocks where added.
    /// * A Report Block is erroneous.
    /// * The padding is not a multiple of 4.
    pub fn write_into(self, buf: &mut [u8]) -> Result<usize, RtcpWriteError> {
        let req_size = self.calculate_size()?;
        if buf.len() < req_size {
            return Err(RtcpWriteError::OutputTooSmall(req_size));
        }

        Ok(self.write_into_unchecked(&mut buf[..req_size]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_rr() {
        let data = [0x80, 0xc9, 0x00, 0x01, 0x91, 0x82, 0x73, 0x64];
        let rr = ReceiverReport::parse(&data).unwrap();
        assert_eq!(rr.version(), 2);
        assert_eq!(rr.padding(), None);
        assert_eq!(rr.n_reports(), 0);
        assert_eq!(rr.report_blocks().count(), 0);
    }

    #[test]
    fn build_empty_rr() {
        const REQ_LEN: usize = ReceiverReport::MIN_PACKET_LEN;
        let rrb = ReceiverReport::builder(0x91827364);
        let req_len = rrb.calculate_size().unwrap();
        assert_eq!(req_len, REQ_LEN);

        let mut data = [0; REQ_LEN];
        let len = rrb.write_into(&mut data).unwrap();
        assert_eq!(len, REQ_LEN);
        assert_eq!(data, [0x80, 0xc9, 0x00, 0x01, 0x91, 0x82, 0x73, 0x64]);
    }

    #[test]
    fn build_2_blocks_rr() {
        let rb1 = ReportBlock::builder(0x1234567);
        let rb2 = ReportBlock::builder(0x1234568);

        const REQ_LEN: usize = ReceiverReport::MIN_PACKET_LEN + ReportBlock::EXPECTED_SIZE * 2;
        let rrb = ReceiverReport::builder(0x91827364)
            .add_report_block(rb1)
            .add_report_block(rb2);
        let req_len = rrb.calculate_size().unwrap();
        assert_eq!(req_len, REQ_LEN);

        let mut data = [0; REQ_LEN];
        let len = rrb.write_into(&mut data).unwrap();
        assert_eq!(len, REQ_LEN);
        assert_eq!(
            data,
            [
                0x82, 0xc9, 0x00, 0x0d, 0x91, 0x82, 0x73, 0x64, 0x01, 0x23, 0x45, 0x67, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x01, 0x23, 0x45, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        );
    }

    #[test]
    fn build_2_blocks_padded_rr() {
        let rb1 = ReportBlock::builder(0x1234567);
        let rb2 = ReportBlock::builder(0x1234568);

        const PADDING: usize = 4;
        const REQ_LEN: usize =
            ReceiverReport::MIN_PACKET_LEN + ReportBlock::EXPECTED_SIZE * 2 + PADDING;
        let rrb = ReceiverReport::builder(0x91827364)
            .padding(PADDING as u8)
            .add_report_block(rb1)
            .add_report_block(rb2);
        let req_len = rrb.calculate_size().unwrap();
        assert_eq!(req_len, REQ_LEN);

        let mut data = [0; REQ_LEN];
        let len = rrb.write_into(&mut data).unwrap();
        assert_eq!(len, REQ_LEN);
        assert_eq!(
            data,
            [
                0xa2, 0xc9, 0x00, 0x0e, 0x91, 0x82, 0x73, 0x64, 0x01, 0x23, 0x45, 0x67, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x01, 0x23, 0x45, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x04,
            ]
        );
    }

    #[test]
    fn parse_rr_short() {
        assert_eq!(
            ReceiverReport::parse(&[0]),
            Err(RtcpParseError::Truncated {
                expected: 8,
                actual: 1
            })
        );
    }

    #[test]
    fn build_too_many_report_blocks() {
        let mut b = ReceiverReport::builder(0);
        for _ in 0..ReceiverReport::MAX_REPORTS as usize + 1 {
            b = b.add_report_block(ReportBlock::builder(1));
        }
        let err = b.calculate_size().unwrap_err();
        assert_eq!(
            err,
            RtcpWriteError::TooManyReportBlocks {
                count: ReceiverReport::MAX_REPORTS as usize + 1,
                max: ReceiverReport::MAX_REPORTS
            }
        );
    }

    #[test]
    fn build_erroneous_report() {
        let b = ReceiverReport::builder(0)
            .add_report_block(ReportBlock::builder(1).cumulative_lost(0xffffff + 1));
        let err = b.calculate_size().unwrap_err();
        assert_eq!(
            err,
            RtcpWriteError::CumulativeLostTooLarge {
                value: 0xffffff + 1,
                max: 0xffffff,
            }
        );
    }

    #[test]
    fn build_padding_not_multiple_4() {
        let b = ReceiverReport::builder(0).padding(5);
        let err = b.calculate_size().unwrap_err();
        assert_eq!(err, RtcpWriteError::InvalidPadding { padding: 5 });
    }
}
