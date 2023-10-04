// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{utils::u32_from_be_bytes, RtcpParseError};

pub struct Bye<'a> {
    data: &'a [u8],
}

impl<'a> Bye<'a> {
    const MIN_PACKET_LEN: usize = 4;
    pub(crate) const PACKET_TYPE: u8 = 203;

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
        Ok(ret)
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

    pub fn version(&self) -> u8 {
        self.data[0] >> 6
    }

    pub fn count(&self) -> u8 {
        self.data[0] & 0x1f
    }

    fn length(&self) -> u8 {
        self.data[5]
    }

    pub fn ssrcs(&self) -> impl Iterator<Item = u32> + '_ {
        self.data[4..4 + self.count() as usize * 4]
            .chunks_exact(4)
            .map(u32_from_be_bytes)
    }

    pub fn reason(&self) -> Option<&[u8]> {
        if self.count() < self.length() {
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
