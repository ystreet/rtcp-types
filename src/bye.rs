// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    utils::{parser::*, u32_from_be_bytes},
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

    pub fn reason_length(&self) -> u8 {
        self.data[5]
    }

    pub fn reason(&self) -> Option<&[u8]> {
        if self.count() < self.reason_length() {
            let offset = self.count() as usize * 4 + 4;
            let len = self.data[offset] as usize;
            Some(&self.data[offset + 1..len])
        } else {
            None
        }
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
    }
}
