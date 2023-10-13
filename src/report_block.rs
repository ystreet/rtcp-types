// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{utils::u32_from_be_bytes, RtcpParseError};

#[derive(Debug, PartialEq, Eq)]
pub struct ReportBlock<'a> {
    data: &'a [u8],
}

impl<'a> ReportBlock<'a> {
    pub const EXPECTED_SIZE: usize = 24;

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
        let ret = Self { data };
        Ok(ret)
    }

    pub fn ssrc(&self) -> u32 {
        u32_from_be_bytes(self.data[0..4].as_ref())
    }

    pub fn fraction_lost(&self) -> u8 {
        self.data[4]
    }

    pub fn cumulative_lost(&self) -> u32 {
        u32_from_be_bytes(self.data[4..8].as_ref()) & 0xffffff
    }

    pub fn extended_sequence_number(&self) -> u32 {
        u32_from_be_bytes(self.data[8..12].as_ref())
    }

    pub fn interarrival_jitter(&self) -> u32 {
        u32_from_be_bytes(self.data[12..16].as_ref())
    }

    pub fn last_sender_report_timestamp(&self) -> u32 {
        u32_from_be_bytes(self.data[16..20].as_ref())
    }

    pub fn delay_since_last_sender_report_timestamp(&self) -> u32 {
        u32_from_be_bytes(self.data[20..24].as_ref())
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
