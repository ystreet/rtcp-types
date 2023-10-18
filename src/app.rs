// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    utils::{data_to_string, parser::*},
    RtcpPacket, RtcpParseError,
};

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

    pub fn get_name_string(&self) -> Result<String, std::string::FromUtf8Error> {
        data_to_string(&self.name())
    }

    pub fn data(&self) -> &[u8] {
        &self.data[12..self.data.len() - self.padding().unwrap_or(0) as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_app() {
        let data = [
            0x80, 0xcc, 0x00, 0x02, 0x91, 0x82, 0x73, 0x64, 0x00, 0x00, 0x00, 0x00,
        ];
        let app = App::parse(&data).unwrap();
        assert_eq!(app.version(), 2);
        assert_eq!(app.padding(), None);
        assert_eq!(app.subtype(), 0);
        assert_eq!(app.name(), [0, 0, 0, 0]);
        assert!(app.get_name_string().unwrap().is_empty());
        assert!(app.data().is_empty());
    }

    #[test]
    fn parse_app() {
        let data = [
            0xbf, 0xcc, 0x00, 0x04, 0x91, 0x82, 0x73, 0x64, 0x6e, 0x61, 0x6d, 0x65, 0x01, 0x02,
            0x03, 0x00, 0x00, 0x00, 0x00, 0x04,
        ];
        let app = App::parse(&data).unwrap();
        assert_eq!(app.version(), 2);
        assert_eq!(app.padding(), Some(4));
        assert_eq!(app.subtype(), 31);
        assert_eq!(app.name(), "name".as_bytes());
        assert_eq!(app.get_name_string().unwrap(), "name");
        assert_eq!(app.data(), [0x01, 0x02, 0x3, 0x0]);
    }
}
