// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{utils::u32_from_be_bytes, RtcpParseError};

pub struct App<'a> {
    data: &'a [u8],
}

impl<'a> App<'a> {
    const MIN_PACKET_LEN: usize = 12;
    pub(crate) const PACKET_TYPE: u8 = 204;

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

    pub fn subtype(&self) -> u8 {
        self.data[0] & 0x1f
    }

    pub fn ssrc(&self) -> u32 {
        u32_from_be_bytes(&self.data[4..8])
    }

    pub fn name(&self) -> [u8; 4] {
        self.data[8..12].try_into().unwrap()
    }

    pub fn data(&self) -> &[u8] {
        &self.data[12..]
    }
}
