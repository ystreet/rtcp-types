// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    utils::{u16_from_be_bytes, u32_from_be_bytes, u64_from_be_bytes},
    RtcpParseError,
};

#[derive(Debug, PartialEq, Eq)]
pub struct SenderReport<'a> {
    data: &'a [u8],
}

impl<'a> SenderReport<'a> {
    const MIN_PACKET_LEN: usize = 28;
    pub(crate) const PACKET_TYPE: u8 = 200;

    pub fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        if data.len() < Self::MIN_PACKET_LEN {
            return Err(RtcpParseError::Truncated {
                expected: Self::MIN_PACKET_LEN,
                actual: data.len(),
            });
        }
        let ret = Self { data };
        if ret.version() != 2 {
            return Err(RtcpParseError::UnsupportedVersion(ret.version()));
        }
        if ret.data[1] != Self::PACKET_TYPE {
            return Err(RtcpParseError::WrongImplementation);
        }
        if data.len() < ret.length() {
            return Err(RtcpParseError::Truncated {
                expected: ret.length(),
                actual: data.len(),
            });
        }
        if data.len() > ret.length() {
            return Err(RtcpParseError::TooLarge {
                expected: ret.length(),
                actual: data.len(),
            });
        }
        Ok(ret)
    }

    pub fn version(&self) -> u8 {
        self.data[0] >> 6
    }

    fn padding_bit(&self) -> bool {
        (self.data[0] & 0x20) != 0
    }

    pub fn padding(&self) -> Option<u8> {
        if self.padding_bit() {
            Some(self.data[self.data.len() - 1])
        } else {
            None
        }
    }

    pub fn n_records(&self) -> u8 {
        self.data[0] & 0x1f
    }

    fn length(&self) -> usize {
        4 * ((u16_from_be_bytes(self.data[2..4].as_ref()) as usize) + 1)
    }

    pub fn ssrc(&self) -> u32 {
        u32_from_be_bytes(self.data[4..8].as_ref())
    }

    pub fn ntp_timestamp(&self) -> u64 {
        u64_from_be_bytes(self.data[8..16].as_ref())
    }

    pub fn rtp_timestamp(&self) -> u32 {
        u32_from_be_bytes(self.data[16..20].as_ref())
    }

    pub fn packet_count(&self) -> u32 {
        u32_from_be_bytes(self.data[20..24].as_ref())
    }

    pub fn octet_count(&self) -> u32 {
        u32_from_be_bytes(self.data[24..28].as_ref())
    }

    pub fn record_blocks(&self) -> impl Iterator<Item = ReportBlock<'a>> + '_ {
        self.data[28..28 + (self.n_records() as usize * 24)]
            .chunks_exact(24)
            .map(|b| ReportBlock::parse(b).unwrap())
    }
}

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
        u32_from_be_bytes(self.data)
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

    #[test]
    fn parse_sr_no_report_blocks() {
        let data = [
            0x80, // VERSION | PADDING | N_RECORDS
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
        assert_eq!(sr.n_records(), 0);
        assert_eq!(sr.ssrc(), 0x01234567);
        assert_eq!(sr.ntp_timestamp(), 0x89abcdef02244668);
        assert_eq!(sr.rtp_timestamp(), 0x8aaccee0);
        assert_eq!(sr.packet_count(), 0xf1e2d3c4);
        assert_eq!(sr.octet_count(), 0xb5a69788);
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
}
