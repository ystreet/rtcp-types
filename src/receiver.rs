// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{utils::u16_from_be_bytes, ReportBlock, RtcpParseError};

#[derive(Debug, PartialEq, Eq)]
pub struct ReceiverReport<'a> {
    data: &'a [u8],
}

impl<'a> ReceiverReport<'a> {
    const MIN_PACKET_LEN: usize = 8;
    pub(crate) const PACKET_TYPE: u8 = 201;

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
