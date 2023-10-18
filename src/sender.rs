// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    utils::{parser::*, u32_from_be_bytes, u64_from_be_bytes},
    ReportBlock, RtcpPacket, RtcpParseError,
};

/// A Parsed Sender Report packet.
#[derive(Debug, PartialEq, Eq)]
pub struct SenderReport<'a> {
    data: &'a [u8],
}

impl<'a> RtcpPacket for SenderReport<'a> {
    const MIN_PACKET_LEN: usize = 28;
    const PACKET_TYPE: u8 = 200;
}

impl<'a> SenderReport<'a> {
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

    pub fn n_records(&self) -> u8 {
        parse_count(self.data)
    }

    pub fn length(&self) -> usize {
        parse_length(self.data)
    }

    pub fn ssrc(&self) -> u32 {
        parse_ssrc(self.data)
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

    pub fn record_blocks(&self) -> impl Iterator<Item = ReportBlock<'a>> + '_ {
        self.data[28..28 + (self.n_records() as usize * 24)]
            .chunks_exact(24)
            .map(|b| ReportBlock::parse(b).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
