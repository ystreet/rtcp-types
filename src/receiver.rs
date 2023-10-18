// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{utils::parser::*, ReportBlock, RtcpPacket, RtcpParseError};

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

    pub fn record_blocks(&self) -> impl Iterator<Item = ReportBlock<'a>> + '_ {
        self.data[8..8 + (self.n_records() as usize * 24)]
            .chunks_exact(24)
            .map(|b| ReportBlock::parse(b).unwrap())
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
        assert_eq!(rr.n_records(), 0);
        assert_eq!(rr.record_blocks().count(), 0);
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
}
