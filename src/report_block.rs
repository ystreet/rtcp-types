// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{utils::u32_from_be_bytes, RtcpParseError, RtcpWriteError};

/// A report block as found in a [`SenderReport`](crate::SenderReport) or a
/// [`ReceiverReport`](crate::ReceiverReport) for a received SSRC
#[derive(Debug, PartialEq, Eq)]
pub struct ReportBlock<'a> {
    data: &'a [u8; ReportBlock::EXPECTED_SIZE],
}

impl<'a> ReportBlock<'a> {
    pub const EXPECTED_SIZE: usize = 24;

    /// Parse data into a [`ReportBlock`].
    pub fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        if data.len() < Self::EXPECTED_SIZE {
            return Err(RtcpParseError::Truncated {
                expected: Self::EXPECTED_SIZE,
                actual: data.len(),
            });
        }
        if data.len() > Self::EXPECTED_SIZE {
            return Err(RtcpParseError::TooLarge {
                expected: Self::EXPECTED_SIZE,
                actual: data.len(),
            });
        }
        Ok(Self {
            data: data.try_into().unwrap(),
        })
    }

    /// The SSRC that this report describes
    pub fn ssrc(&self) -> u32 {
        u32_from_be_bytes(&self.data[0..4])
    }

    /// The fractional part (out of 256) of packets that have been lost
    pub fn fraction_lost(&self) -> u8 {
        self.data[4]
    }

    /// Total count of packets that have been lost.  This is a 24-bit value.
    pub fn cumulative_lost(&self) -> u32 {
        u32_from_be_bytes(&self.data[4..8]) & 0xffffff
    }

    /// Extended sequence number
    pub fn extended_sequence_number(&self) -> u32 {
        u32_from_be_bytes(&self.data[8..12])
    }

    /// The interarrival jitter of this receiver
    pub fn interarrival_jitter(&self) -> u32 {
        u32_from_be_bytes(&self.data[12..16])
    }

    /// The NTP 16.16 fixed point time that a sender report was last received
    pub fn last_sender_report_timestamp(&self) -> u32 {
        u32_from_be_bytes(&self.data[16..20])
    }

    /// 16.16 fixed point duration since the last sender report was received
    pub fn delay_since_last_sender_report_timestamp(&self) -> u32 {
        u32_from_be_bytes(&self.data[20..24])
    }

    /// Create a new [`ReportBlockBuilder`]
    pub fn builder(ssrc: u32) -> ReportBlockBuilder {
        ReportBlockBuilder::new(ssrc)
    }
}

/// Report Block Builder
#[derive(Debug, Eq, PartialEq)]
#[must_use = "The builder must be built to be used"]
pub struct ReportBlockBuilder {
    ssrc: u32,
    fraction_lost: u8,
    cumulative_lost: u32,
    extended_sequence_number: u32,
    interarrival_jitter: u32,
    last_sender_report_timestamp: u32,
    delay_since_last_sender_report_timestamp: u32,
}

impl ReportBlockBuilder {
    pub fn new(ssrc: u32) -> Self {
        ReportBlockBuilder {
            ssrc,
            fraction_lost: 0,
            cumulative_lost: 0,
            extended_sequence_number: 0,
            interarrival_jitter: 0,
            last_sender_report_timestamp: 0,
            delay_since_last_sender_report_timestamp: 0,
        }
    }

    /// The fraction (out of 256) of packets lost
    pub fn fraction_lost(mut self, fraction_lost: u8) -> Self {
        self.fraction_lost = fraction_lost;
        self
    }

    /// The cumulative count of packets lost.  Value must be limited to the sie of a 24-bit value.
    pub fn cumulative_lost(mut self, cumulative_lost: u32) -> Self {
        self.cumulative_lost = cumulative_lost;
        self
    }

    /// The extended sequence number
    pub fn extended_sequence_number(mut self, extended_sequence_number: u32) -> Self {
        self.extended_sequence_number = extended_sequence_number;
        self
    }

    /// The inter arrival jitter
    pub fn interarrival_jitter(mut self, interarrival_jitter: u32) -> Self {
        self.interarrival_jitter = interarrival_jitter;
        self
    }

    /// The NTP 16.16 fixed point time of the last sender report
    pub fn last_sender_report_timestamp(mut self, last_sender_report_timestamp: u32) -> Self {
        self.last_sender_report_timestamp = last_sender_report_timestamp;
        self
    }

    /// The NTP 16.16 fixed point duration since the last sender report
    pub fn delay_since_last_sender_report_timestamp(
        mut self,
        delay_since_last_sender_report_timestamp: u32,
    ) -> Self {
        self.delay_since_last_sender_report_timestamp = delay_since_last_sender_report_timestamp;
        self
    }

    /// Calculates the size required to write this Report Block.
    ///
    /// Returns an error if:
    ///
    /// * The cumulative_lost is out of range.
    pub(crate) fn calculate_size(&self) -> Result<usize, RtcpWriteError> {
        if self.cumulative_lost & !0xffffff != 0 {
            return Err(RtcpWriteError::CumulativeLostTooLarge {
                value: self.cumulative_lost,
                max: 0xffffff,
            });
        }

        Ok(ReportBlock::EXPECTED_SIZE)
    }

    /// Writes this Report Block into `buf` without any validity checks.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Panic
    ///
    /// Panics if the buf is not large enough.
    #[inline]
    pub(crate) fn write_into_unchecked(&self, buf: &mut [u8]) -> usize {
        buf[0..4].copy_from_slice(&self.ssrc.to_be_bytes());
        buf[4..8].copy_from_slice(&self.cumulative_lost.to_be_bytes());
        buf[4] = self.fraction_lost;
        buf[8..12].copy_from_slice(&self.extended_sequence_number.to_be_bytes());
        buf[12..16].copy_from_slice(&self.interarrival_jitter.to_be_bytes());
        buf[16..20].copy_from_slice(&self.last_sender_report_timestamp.to_be_bytes());
        buf[20..].copy_from_slice(&self.delay_since_last_sender_report_timestamp.to_be_bytes());

        ReportBlock::EXPECTED_SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_report_block() {
        let data = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x02, 0x24, 0x46, 0x68, 0x8a, 0xac,
            0xce, 0xe0, 0xf1, 0xd3, 0xb5, 0x97, 0x79, 0x5b, 0x3d, 0x1f,
        ];
        let rb = ReportBlock::parse(&data).unwrap();
        assert_eq!(rb.ssrc(), 0x1234567);
        assert_eq!(rb.fraction_lost(), 0x89);
        assert_eq!(rb.cumulative_lost(), 0xabcdef);
        assert_eq!(rb.extended_sequence_number(), 0x02244668);
        assert_eq!(rb.interarrival_jitter(), 0x8aaccee0);
        assert_eq!(rb.last_sender_report_timestamp(), 0xf1d3b597);
        assert_eq!(rb.delay_since_last_sender_report_timestamp(), 0x795b3d1f);
    }

    #[test]
    fn build_report_block() {
        let rbb = ReportBlock::builder(0x1234567)
            .fraction_lost(0x89)
            .cumulative_lost(0xabcdef)
            .extended_sequence_number(0x02244668)
            .interarrival_jitter(0x8aaccee0)
            .last_sender_report_timestamp(0xf1d3b597)
            .delay_since_last_sender_report_timestamp(0x795b3d1f);
        let req_size = rbb.calculate_size().unwrap();
        assert_eq!(req_size, ReportBlock::EXPECTED_SIZE);

        let mut buf = [0; ReportBlock::EXPECTED_SIZE];
        let len = rbb.write_into_unchecked(&mut buf);
        assert_eq!(len, ReportBlock::EXPECTED_SIZE);
        assert_eq!(
            buf,
            [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x02, 0x24, 0x46, 0x68, 0x8a, 0xac,
                0xce, 0xe0, 0xf1, 0xd3, 0xb5, 0x97, 0x79, 0x5b, 0x3d, 0x1f,
            ]
        );
    }

    #[test]
    fn short_report_block() {
        assert_eq!(
            ReportBlock::parse(&[0]),
            Err(RtcpParseError::Truncated {
                expected: 24,
                actual: 1
            })
        );
    }

    #[test]
    fn too_large_report_block() {
        let data = [0; 25];
        assert_eq!(
            ReportBlock::parse(&data),
            Err(RtcpParseError::TooLarge {
                expected: 24,
                actual: 25
            })
        );
    }
}
