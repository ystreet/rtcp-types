// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{utils::u16_from_be_bytes, RtcpParseError};

pub struct Unknown<'a> {
    data: &'a [u8],
}

impl<'a> Unknown<'a> {
    const MIN_PACKET_LEN: usize = 4;

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

    pub fn type_(&self) -> u8 {
        self.data[1]
    }

    fn length(&self) -> u16 {
        u16_from_be_bytes(&self.data[2..4])
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
        self.offset += (packet.length() as usize + 1) * 4;
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
