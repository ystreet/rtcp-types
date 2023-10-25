// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    prelude::*,
    utils::{parser, u32_from_be_bytes, u64_from_be_bytes, writer},
    ReportBlock, ReportBlockBuilder, RtcpPacket, RtcpParseError, RtcpWriteError,
};

/// A Parsed Sender Report packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SenderReport<'a> {
    data: &'a [u8],
}

impl<'a> RtcpPacket for SenderReport<'a> {
    const MIN_PACKET_LEN: usize = 28;
    const PACKET_TYPE: u8 = 200;
}

impl<'a> RtcpPacketParser<'a> for SenderReport<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        parser::check_packet::<Self>(data)?;

        let req_len =
            Self::MIN_PACKET_LEN + parser::parse_count(data) as usize * ReportBlock::EXPECTED_SIZE;
        if data.len() < req_len {
            return Err(RtcpParseError::Truncated {
                expected: req_len,
                actual: data.len(),
            });
        }

        Ok(Self { data })
    }

    #[inline(always)]
    fn header_data(&self) -> [u8; 4] {
        self.data[..4].try_into().unwrap()
    }
}

impl<'a> SenderReport<'a> {
    const MAX_REPORTS: u8 = Self::MAX_COUNT;

    pub fn padding(&self) -> Option<u8> {
        parser::parse_padding(self.data)
    }

    pub fn n_reports(&self) -> u8 {
        self.count()
    }

    pub fn ssrc(&self) -> u32 {
        parser::parse_ssrc(self.data)
    }

    pub fn ntp_timestamp(&self) -> u64 {
        u64_from_be_bytes(&self.data[8..16])
    }

    pub fn rtp_timestamp(&self) -> u32 {
        u32_from_be_bytes(&self.data[16..20])
    }

    pub fn packet_count(&self) -> u32 {
        u32_from_be_bytes(&self.data[20..24])
    }

    pub fn octet_count(&self) -> u32 {
        u32_from_be_bytes(&self.data[24..28])
    }

    pub fn report_blocks(&self) -> impl Iterator<Item = ReportBlock<'a>> + '_ {
        self.data[Self::MIN_PACKET_LEN..Self::MIN_PACKET_LEN + (self.n_reports() as usize * 24)]
            .chunks_exact(24)
            .map(|b| ReportBlock::parse(b).unwrap())
    }

    pub fn builder(ssrc: u32) -> SenderReportBuilder {
        SenderReportBuilder::new(ssrc)
    }
}

/// Sender Report Builder
#[derive(Debug)]
pub struct SenderReportBuilder {
    ssrc: u32,
    padding: u8,
    ntp_timestamp: u64,
    rtp_timestamp: u32,
    packet_count: u32,
    octet_count: u32,
    report_blocks: Vec<ReportBlockBuilder>,
}

impl SenderReportBuilder {
    fn new(ssrc: u32) -> Self {
        SenderReportBuilder {
            ssrc,
            padding: 0,
            ntp_timestamp: 0,
            rtp_timestamp: 0,
            packet_count: 0,
            octet_count: 0,
            report_blocks: Vec::with_capacity(SenderReport::MAX_REPORTS as usize),
        }
    }

    /// Sets the number of padding bytes to use for this Sender Report.
    pub fn padding(mut self, padding: u8) -> Self {
        self.padding = padding;
        self
    }

    /// Sets the ntp_timestamp for this Sender Report.
    pub fn ntp_timestamp(mut self, ntp_timestamp: u64) -> Self {
        self.ntp_timestamp = ntp_timestamp;
        self
    }

    /// Sets the ntp_timestamp for this Sender Report.
    pub fn rtp_timestamp(mut self, rtp_timestamp: u32) -> Self {
        self.rtp_timestamp = rtp_timestamp;
        self
    }

    /// Sets the packet_count for this Sender Report.
    pub fn packet_count(mut self, packet_count: u32) -> Self {
        self.packet_count = packet_count;
        self
    }

    /// Sets the octet_count for this Sender Report.
    pub fn octet_count(mut self, octet_count: u32) -> Self {
        self.octet_count = octet_count;
        self
    }

    /// Adds the provided Report Block.
    pub fn add_report_block(mut self, report_block: ReportBlockBuilder) -> Self {
        self.report_blocks.push(report_block);
        self
    }
}

impl RtcpPacketWriter for SenderReportBuilder {
    /// Calculates the size required to write this Sender Report packet.
    ///
    /// Returns an error if:
    ///
    /// * Too many Report Blocks where added.
    /// * A Report Block is erroneous.
    /// * The padding is not a multiple of 4.
    fn calculate_size(&self) -> Result<usize, RtcpWriteError> {
        if self.report_blocks.len() > SenderReport::MAX_REPORTS as usize {
            return Err(RtcpWriteError::TooManyReportBlocks {
                count: self.report_blocks.len(),
                max: SenderReport::MAX_REPORTS,
            });
        }

        writer::check_padding(self.padding)?;

        let mut report_blocks_size = 0;
        for rb in self.report_blocks.iter() {
            report_blocks_size += rb.calculate_size()?;
        }

        Ok(SenderReport::MIN_PACKET_LEN + report_blocks_size + self.padding as usize)
    }

    /// Write this Sender Report into `buf` without any validity checks.
    ///
    /// Uses the length of the buffer for the length field.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Panic
    ///
    /// Panics if the buf is not large enough.
    #[inline]
    fn write_into_unchecked(&self, buf: &mut [u8]) -> usize {
        writer::write_header_unchecked::<SenderReport>(
            self.padding,
            self.report_blocks.len() as u8,
            buf,
        );

        buf[4..8].copy_from_slice(&self.ssrc.to_be_bytes());
        buf[8..16].copy_from_slice(&self.ntp_timestamp.to_be_bytes());
        buf[16..20].copy_from_slice(&self.rtp_timestamp.to_be_bytes());
        buf[20..24].copy_from_slice(&self.packet_count.to_be_bytes());
        buf[24..28].copy_from_slice(&self.octet_count.to_be_bytes());

        let mut idx = 28;
        let mut end = idx;
        for report_block in self.report_blocks.iter() {
            end += ReportBlock::EXPECTED_SIZE;
            report_block.write_into_unchecked(&mut buf[idx..end]);
            idx = end;
        }

        end += writer::write_padding_unchecked(self.padding, &mut buf[idx..]);

        end
    }

    fn get_padding(&self) -> Option<u8> {
        if self.padding == 0 {
            return None;
        }

        Some(self.padding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sr_no_report_blocks() {
        let data = [
            0x80, // VERSION | PADDING | N_REPORTS
            0xc8, // PT=SR
            0x00, 0x06, // LENGTH
            0x01, 0x23, 0x45, 0x67, // SSRC
            0x89, 0xab, 0xcd, 0xef, 0x02, 0x24, 0x46, 0x68, // NTP timestamp
            0x8a, 0xac, 0xce, 0xe0, // RTP timestamp
            0xf1, 0xe2, 0xd3, 0xc4, // packet count
            0xb5, 0xa6, 0x97, 0x88, // octet count
        ];
        let sr = SenderReport::parse(&data).unwrap();
        assert_eq!(sr.version(), 2);
        assert_eq!(sr.padding(), None);
        assert_eq!(sr.n_reports(), 0);
        assert_eq!(sr.ssrc(), 0x01234567);
        assert_eq!(sr.ntp_timestamp(), 0x89abcdef02244668);
        assert_eq!(sr.rtp_timestamp(), 0x8aaccee0);
        assert_eq!(sr.packet_count(), 0xf1e2d3c4);
        assert_eq!(sr.octet_count(), 0xb5a69788);
    }

    #[test]
    fn build_empty_sr() {
        const REQ_LEN: usize = SenderReport::MIN_PACKET_LEN;
        let srb = SenderReport::builder(0x01234567)
            .ntp_timestamp(0x89abcdef02244668)
            .rtp_timestamp(0x8aaccee0)
            .packet_count(0xf1e2d3c4)
            .octet_count(0xb5a69788);
        let req_len = srb.calculate_size().unwrap();
        assert_eq!(req_len, REQ_LEN);

        let mut data = [0; REQ_LEN];
        let len = srb.write_into(&mut data).unwrap();
        assert_eq!(len, REQ_LEN);
        assert_eq!(
            data,
            [
                0x80, // VERSION | PADDING | N_REPORTS
                0xc8, // PT=SR
                0x00, 0x06, // LENGTH
                0x01, 0x23, 0x45, 0x67, // SSRC
                0x89, 0xab, 0xcd, 0xef, 0x02, 0x24, 0x46, 0x68, // NTP timestamp
                0x8a, 0xac, 0xce, 0xe0, // RTP timestamp
                0xf1, 0xe2, 0xd3, 0xc4, // packet count
                0xb5, 0xa6, 0x97, 0x88, // octet count
            ]
        );
    }

    #[test]
    fn build_2_blocks_sr() {
        let rb1 = ReportBlock::builder(0x1234567);
        let rb2 = ReportBlock::builder(0x1234568);

        const REQ_LEN: usize = SenderReport::MIN_PACKET_LEN + ReportBlock::EXPECTED_SIZE * 2;
        let srb = SenderReport::builder(0x91827364)
            .ntp_timestamp(0x89abcdef02244668)
            .rtp_timestamp(0x8aaccee0)
            .packet_count(0xf1e2d3c4)
            .octet_count(0xb5a69788)
            .add_report_block(rb1)
            .add_report_block(rb2);

        let req_len = srb.calculate_size().unwrap();
        assert_eq!(req_len, REQ_LEN);

        let mut data = [0; REQ_LEN];
        let len = srb.write_into(&mut data).unwrap();
        assert_eq!(len, REQ_LEN);
        assert_eq!(
            data,
            [
                0x82, 0xc8, 0x00, 0x12, 0x91, 0x82, 0x73, 0x64, 0x89, 0xab, 0xcd, 0xef, 0x02, 0x24,
                0x46, 0x68, 0x8a, 0xac, 0xce, 0xe0, 0xf1, 0xe2, 0xd3, 0xc4, 0xb5, 0xa6, 0x97, 0x88,
                0x01, 0x23, 0x45, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x23, 0x45, 0x68,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        );
    }

    #[test]
    fn build_2_blocks_padded_sr() {
        let rb1 = ReportBlock::builder(0x1234567);
        let rb2 = ReportBlock::builder(0x1234568);

        const PADDING: usize = 4;
        const REQ_LEN: usize =
            SenderReport::MIN_PACKET_LEN + ReportBlock::EXPECTED_SIZE * 2 + PADDING;
        let srb = SenderReport::builder(0x91827364)
            .padding(PADDING as u8)
            .add_report_block(rb1)
            .add_report_block(rb2);

        let req_len = srb.calculate_size().unwrap();
        assert_eq!(req_len, REQ_LEN);

        let mut data = [0; REQ_LEN];
        let len = srb.write_into(&mut data).unwrap();
        assert_eq!(len, REQ_LEN);
        assert_eq!(
            data,
            [
                0xa2, 0xc8, 0x00, 0x13, 0x91, 0x82, 0x73, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x01, 0x23, 0x45, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x23, 0x45, 0x68,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
            ]
        );
    }

    #[test]
    fn parse_sr_short() {
        assert_eq!(
            SenderReport::parse(&[0x80]),
            Err(RtcpParseError::Truncated {
                expected: 28,
                actual: 1
            })
        );
    }

    #[test]
    fn parse_sr_too_short_for_report_count() {
        assert_eq!(
            SenderReport::parse(&[
                0x82, 0xc8, 0x00, 0x12, 0x91, 0x82, 0x73, 0x64, 0x89, 0xab, 0xcd, 0xef, 0x02, 0x24,
                0x46, 0x68, 0x8a, 0xac, 0xce, 0xe0, 0xf1, 0xe2, 0xd3, 0xc4, 0xb5, 0xa6, 0x97, 0x88,
                0x01, 0x23, 0x45, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            ]),
            Err(RtcpParseError::Truncated {
                expected: 76,
                actual: 53
            })
        );
    }

    #[test]
    fn build_too_many_report_blocks() {
        let mut b = SenderReport::builder(0);
        for _ in 0..SenderReport::MAX_REPORTS as usize + 1 {
            b = b.add_report_block(ReportBlock::builder(1));
        }
        let err = b.calculate_size().unwrap_err();
        assert_eq!(
            err,
            RtcpWriteError::TooManyReportBlocks {
                count: SenderReport::MAX_REPORTS as usize + 1,
                max: SenderReport::MAX_REPORTS
            }
        );
    }

    #[test]
    fn build_erroneous_report() {
        let b = SenderReport::builder(0)
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
        let b = SenderReport::builder(0).padding(5);
        let err = b.calculate_size().unwrap_err();
        assert_eq!(err, RtcpWriteError::InvalidPadding { padding: 5 });
    }

    #[test]
    fn parse_sr_with_2_rb() {
        let sr = SenderReport::parse(&[
            0x82, 0xc8, 0x00, 0x12, 0x91, 0x82, 0x73, 0x64, 0x89, 0xab, 0xcd, 0xef, 0x02, 0x24,
            0x46, 0x68, 0x8a, 0xac, 0xce, 0xe0, 0xf1, 0xe2, 0xd3, 0xc4, 0xb5, 0xa6, 0x97, 0x88,
            0x01, 0x23, 0x45, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x23, 0x45, 0x68,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        .unwrap();
        assert_eq!(sr.version(), 2);
        assert_eq!(sr.padding(), None);
        assert_eq!(sr.n_reports(), 2);
        assert_eq!(sr.length(), 76);
        assert_eq!(sr.ssrc(), 0x91827364);
        assert_eq!(sr.ntp_timestamp(), 0x89abcdef02244668);
        assert_eq!(sr.rtp_timestamp(), 0x8aaccee0);
        assert_eq!(sr.packet_count(), 0xf1e2d3c4);
        assert_eq!(sr.octet_count(), 0xb5a69788);
        let mut rb = sr.report_blocks();
        let rb_item = rb.next().unwrap();
        assert_eq!(rb_item.ssrc(), 0x01234567);
        let rb_item = rb.next().unwrap();
        assert_eq!(rb_item.ssrc(), 0x01234568);
        assert_eq!(rb.next(), None);
    }
}
