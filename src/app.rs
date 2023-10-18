// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{utils::parser::*, RtcpPacket, RtcpParseError};

/// A Parsed App packet.
#[derive(Debug, PartialEq, Eq)]
pub struct App<'a> {
    data: &'a [u8],
}

impl<'a> RtcpPacket for App<'a> {
    const MIN_PACKET_LEN: usize = 12;
    const PACKET_TYPE: u8 = 204;
}

impl<'a> App<'a> {
    pub const NAME_LEN: usize = 4;

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

    pub fn subtype(&self) -> u8 {
        parse_count(self.data)
    }

    pub fn length(&self) -> usize {
        parse_length(self.data)
    }

    pub fn ssrc(&self) -> u32 {
        parse_ssrc(self.data)
    }

    pub fn name(&self) -> [u8; App::NAME_LEN] {
        self.data[8..8 + Self::NAME_LEN].try_into().unwrap()
    }

    pub fn data(&self) -> &[u8] {
        &self.data[12..]
    }
}
