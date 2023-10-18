// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{utils::parser::*, RtcpPacket, RtcpParseError};

#[derive(Debug, PartialEq, Eq)]
pub struct Unknown<'a> {
    data: &'a [u8],
}

impl<'a> RtcpPacket for Unknown<'a> {
    const MIN_PACKET_LEN: usize = 4;
    const PACKET_TYPE: u8 = 255; // Not used
}

impl<'a> Unknown<'a> {
    const MIN_PACKET_LEN: usize = 4;
    const VERSION: u8 = 2;

    pub fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        if data.len() < Self::MIN_PACKET_LEN {
            return Err(RtcpParseError::Truncated {
                expected: Self::MIN_PACKET_LEN,
                actual: data.len(),
            });
        }

        let version = parse_version(data);
        if parse_version(data) != Self::VERSION {
            return Err(RtcpParseError::UnsupportedVersion(version));
        }

        let length = parse_length(data);
        if data.len() < length {
            return Err(RtcpParseError::Truncated {
                expected: length,
                actual: data.len(),
            });
        }
        if data.len() > length {
            return Err(RtcpParseError::TooLarge {
                expected: length,
                actual: data.len(),
            });
        }

        Ok(Self { data })
    }

    pub fn padding(&self) -> Option<u8> {
        parse_padding(self.data)
    }

    pub fn version(&self) -> u8 {
        parse_version(self.data)
    }

    pub fn type_(&self) -> u8 {
        parse_packet_type(self.data)
    }

    pub fn length(&self) -> usize {
        parse_length(self.data)
    }

    pub fn count(&self) -> u8 {
        parse_count(self.data)
    }

    pub fn data(&self) -> &[u8] {
        self.data
    }
}

pub enum Packet<'a> {
    App(crate::App<'a>),
    Bye(crate::Bye<'a>),
    Rr(crate::ReceiverReport<'a>),
    Sdes(crate::Sdes<'a>),
    Sr(crate::SenderReport<'a>),
    Unknown(Unknown<'a>),
}

pub struct Compound<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Compound<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        let ret = Self { data, offset: 0 };
        Ok(ret)
    }
}

impl<'a> Iterator for Compound<'a> {
    type Item = Packet<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.data.len() {
            return None;
        }
        let packet = match Unknown::parse(&self.data[self.offset..]) {
            Ok(packet) => packet,
            Err(_) => return None,
        };
        self.offset += packet.length();
        Some(match packet.type_() {
            crate::App::PACKET_TYPE => crate::App::parse(packet.data)
                .map(Packet::App)
                .unwrap_or_else(|_| Packet::Unknown(packet)),
            crate::Bye::PACKET_TYPE => crate::Bye::parse(packet.data)
                .map(Packet::Bye)
                .unwrap_or_else(|_| Packet::Unknown(packet)),
            crate::ReceiverReport::PACKET_TYPE => crate::ReceiverReport::parse(packet.data)
                .map(Packet::Rr)
                .unwrap_or_else(|_| Packet::Unknown(packet)),
            crate::Sdes::PACKET_TYPE => crate::Sdes::parse(packet.data)
                .map(Packet::Sdes)
                .unwrap_or_else(|_| Packet::Unknown(packet)),
            crate::SenderReport::PACKET_TYPE => crate::SenderReport::parse(packet.data)
                .map(Packet::Sr)
                .unwrap_or_else(|_| Packet::Unknown(packet)),
            _ => Packet::Unknown(packet),
        })
    }
}
