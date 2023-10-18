// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    utils::{data_to_string, parser::*, u32_from_be_bytes},
    RtcpPacket, RtcpParseError,
};

/// A Parsed Bye packet.
#[derive(Debug, PartialEq, Eq)]
pub struct Bye<'a> {
    data: &'a [u8],
}

impl<'a> RtcpPacket for Bye<'a> {
    const MIN_PACKET_LEN: usize = 4;
    const PACKET_TYPE: u8 = 203;
}

impl<'a> Bye<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        check_packet::<Self>(data)?;

        let reason_len_offset = Self::MIN_PACKET_LEN + 4 * parse_count(data) as usize;
        if reason_len_offset > data.len() {
            return Err(RtcpParseError::Truncated {
                expected: reason_len_offset,
                actual: data.len(),
            });
        }

        if reason_len_offset < data.len() {
            let reason_len = data[reason_len_offset] as usize;
            if reason_len_offset + 1 + reason_len > data.len() {
                return Err(RtcpParseError::Truncated {
                    expected: reason_len_offset + 1 + reason_len,
                    actual: data.len(),
                });
            }
        } // else no reason in this packet

        Ok(Self { data })
    }

    pub fn padding(&self) -> Option<u8> {
        parse_padding(self.data)
    }

    pub fn version(&self) -> u8 {
        parse_version(self.data)
    }

    pub fn count(&self) -> u8 {
        parse_count(self.data)
    }

    pub fn length(&self) -> usize {
        parse_length(self.data)
    }

    pub fn ssrcs(&self) -> impl Iterator<Item = u32> + '_ {
        self.data[4..4 + self.count() as usize * 4]
            .chunks_exact(4)
            .map(u32_from_be_bytes)
    }

    pub fn reason(&self) -> Option<&[u8]> {
        let offset = self.count() as usize * 4 + 4;
        let reason_aligned_len = self
            .length()
            .checked_sub(offset + 1 + self.padding().unwrap_or(0) as usize)?;

        if reason_aligned_len == 0 {
            return None;
        }

        let end = offset + 1 + self.data[offset] as usize;
        Some(&self.data[offset + 1..end])
    }

    pub fn get_reason_string(&self) -> Option<Result<String, std::string::FromUtf8Error>> {
        self.reason().map(data_to_string)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bye_empty() {
        let bye = Bye::parse(&[0x80, 0xcb, 0x00, 0x00]).unwrap();
        assert_eq!(bye.padding(), None);
        assert_eq!(bye.count(), 0);
        assert_eq!(bye.ssrcs().count(), 0);
        assert!(bye.reason().is_none());
        assert!(bye.get_reason_string().is_none());
    }

    #[test]
    fn parse_bye_3_sources() {
        let bye = Bye::parse(&[
            0x83, 0xcb, 0x00, 0x03, 0x12, 0x34, 0x56, 0x78, 0x34, 0x56, 0x78, 0x9a, 0x56, 0x78,
            0x9a, 0xbc,
        ])
        .unwrap();
        assert_eq!(bye.padding(), None);
        assert_eq!(bye.count(), 3);

        let mut ssrc_iter = bye.ssrcs();
        assert_eq!(ssrc_iter.next(), Some(0x12345678));
        assert_eq!(ssrc_iter.next(), Some(0x3456789a));
        assert_eq!(ssrc_iter.next(), Some(0x56789abc));
        assert!(ssrc_iter.next().is_none());

        assert!(bye.reason().is_none());
        assert!(bye.get_reason_string().is_none());
    }

    #[test]
    fn parse_bye_2_sources_reason() {
        let bye = Bye::parse(&[
            0x82, 0xcb, 0x00, 0x05, 0x12, 0x34, 0x56, 0x78, 0x34, 0x56, 0x78, 0x9a, 0x08, 0x53,
            0x68, 0x75, 0x74, 0x64, 0x6f, 0x77, 0x6e, 0x00, 0x00, 0x00,
        ])
        .unwrap();
        assert_eq!(bye.padding(), None);
        assert_eq!(bye.count(), 2);

        let mut ssrc_iter = bye.ssrcs();
        assert_eq!(ssrc_iter.next(), Some(0x12345678));
        assert_eq!(ssrc_iter.next(), Some(0x3456789a));
        assert!(ssrc_iter.next().is_none());

        assert_eq!(String::from_utf8_lossy(bye.reason().unwrap()), "Shutdown");
    }
}
