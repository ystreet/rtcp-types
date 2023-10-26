// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    utils::{parser::*, writer::*},
    RtcpPacket, RtcpParseError, RtcpWriteError,
};

#[derive(Debug, PartialEq, Eq)]
pub struct Unknown<'a> {
    data: &'a [u8],
}

impl<'a> RtcpPacket for Unknown<'a> {
    const MIN_PACKET_LEN: usize = 4;
    const PACKET_TYPE: u8 = 255; // Not used
}

impl<'a> Unknown<'a> {
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

    pub fn builder(type_: u8, data: &'a [u8]) -> UnknownBuilder<'a> {
        UnknownBuilder::new(type_, data)
    }
}

pub struct UnknownBuilder<'a> {
    padding: u8,
    type_: u8,
    count: u8,
    data: &'a [u8],
}

impl<'a> UnknownBuilder<'a> {
    pub fn new(type_: u8, data: &'a [u8]) -> UnknownBuilder<'a> {
        UnknownBuilder {
            padding: 0,
            type_,
            count: 0,
            data,
        }
    }

    pub fn padding(mut self, padding: u8) -> Self {
        self.padding = padding;
        self
    }

    pub fn get_padding(&self) -> u8 {
        self.padding
    }

    pub fn count(mut self, count: u8) -> Self {
        self.count = count;
        self
    }

    /// Calculates the size required to write this Unknown packet.
    ///
    /// Returns an error if:
    ///
    /// * The count is out of range.
    /// * The padding is not a multiple of 4.
    fn calculate_size(&self) -> Result<usize, RtcpWriteError> {
        if self.count > Unknown::MAX_COUNT {
            return Err(RtcpWriteError::CountOutOfRange {
                count: self.count,
                max: Unknown::MAX_COUNT,
            });
        }

        check_padding(self.padding)?;

        Ok(Unknown::MIN_PACKET_LEN + self.data.len())
    }

    /// Write this Unknown packet data into `buf` without any validity checks.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Panic
    ///
    /// Panics if the buf is not large enough.
    #[inline]
    fn write_into_unchecked(&self, buf: &mut [u8]) -> usize {
        write_header_unchecked::<Unknown>(self.padding, self.count, buf);
        buf[1] = self.type_;

        let mut end = 4 + self.data.len();
        buf[4..end].copy_from_slice(self.data);

        end += write_padding_unchecked(self.padding, &mut buf[end..]);

        end
    }

    /// Writes this Unknown packet into `buf`.
    ///
    /// Returns an error if:
    ///
    /// * The buffer is too small.
    /// * The count is out of range.
    /// * The padding is not a multiple of 4.
    pub fn write_into(self, buf: &mut [u8]) -> Result<usize, RtcpWriteError> {
        let req_size = self.calculate_size()?;
        if buf.len() < req_size {
            return Err(RtcpWriteError::OutputTooSmall(req_size));
        }

        Ok(self.write_into_unchecked(&mut buf[..req_size]))
    }
}

#[derive(Debug)]
pub enum Packet<'a> {
    App(crate::App<'a>),
    Bye(crate::Bye<'a>),
    Rr(crate::ReceiverReport<'a>),
    Sdes(crate::Sdes<'a>),
    Sr(crate::SenderReport<'a>),
    Unknown(Unknown<'a>),
}

#[derive(Debug)]
pub struct Compound<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Compound<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        let ret = Self { data, offset: 0 };
        Ok(ret)
    }

    pub fn builder() -> CompoundBuilder<'a> {
        CompoundBuilder::default()
    }
}

impl<'a> Iterator for Compound<'a> {
    type Item = Packet<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.data.len() {
            return None;
        }

        if self.data.len() < self.offset + Unknown::MIN_PACKET_LEN {
            return None;
        }

        let data = &self.data[self.offset..];
        let length = parse_length(data);
        if data.len() < length {
            return None;
        }

        let packet = match Unknown::parse(&data[..length]) {
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

pub enum PacketBuilder<'a> {
    App(crate::app::AppBuilder<'a>),
    Bye(crate::bye::ByeBuilder<'a>),
    Rr(crate::receiver::ReceiverReportBuilder),
    Sdes(crate::sdes::SdesBuilder<'a>),
    Sr(crate::sender::SenderReportBuilder),
    Unknown(UnknownBuilder<'a>),
}

impl<'a> PacketBuilder<'a> {
    pub fn get_padding(&self) -> u8 {
        use PacketBuilder::*;
        match self {
            App(this) => this.get_padding(),
            Bye(this) => this.get_padding(),
            Rr(this) => this.get_padding(),
            Sdes(this) => this.get_padding(),
            Sr(this) => this.get_padding(),
            Unknown(this) => this.get_padding(),
        }
    }

    fn calculate_size(&self) -> Result<usize, RtcpWriteError> {
        use PacketBuilder::*;
        match self {
            App(this) => this.calculate_size(),
            Bye(this) => this.calculate_size(),
            Rr(this) => this.calculate_size(),
            Sdes(this) => this.calculate_size(),
            Sr(this) => this.calculate_size(),
            Unknown(this) => this.calculate_size(),
        }
    }

    fn write_into_unchecked(self, buf: &mut [u8]) -> usize {
        use PacketBuilder::*;
        match self {
            App(this) => this.write_into_unchecked(buf),
            Bye(this) => this.write_into_unchecked(buf),
            Rr(this) => this.write_into_unchecked(buf),
            Sdes(this) => this.write_into_unchecked(buf),
            Sr(this) => this.write_into_unchecked(buf),
            Unknown(this) => this.write_into_unchecked(buf),
        }
    }
}

impl<'a> From<crate::app::AppBuilder<'a>> for PacketBuilder<'a> {
    fn from(pb: crate::app::AppBuilder<'a>) -> Self {
        Self::App(pb)
    }
}

impl<'a> From<crate::bye::ByeBuilder<'a>> for PacketBuilder<'a> {
    fn from(pb: crate::bye::ByeBuilder<'a>) -> Self {
        Self::Bye(pb)
    }
}

impl<'a> From<crate::receiver::ReceiverReportBuilder> for PacketBuilder<'a> {
    fn from(pb: crate::receiver::ReceiverReportBuilder) -> Self {
        Self::Rr(pb)
    }
}

impl<'a> From<crate::sdes::SdesBuilder<'a>> for PacketBuilder<'a> {
    fn from(pb: crate::sdes::SdesBuilder<'a>) -> Self {
        Self::Sdes(pb)
    }
}

impl<'a> From<crate::sender::SenderReportBuilder> for PacketBuilder<'a> {
    fn from(pb: crate::sender::SenderReportBuilder) -> Self {
        Self::Sr(pb)
    }
}

impl<'a> From<UnknownBuilder<'a>> for PacketBuilder<'a> {
    fn from(pb: UnknownBuilder<'a>) -> Self {
        Self::Unknown(pb)
    }
}

#[derive(Default)]
pub struct CompoundBuilder<'a> {
    packets: Vec<PacketBuilder<'a>>,
}

impl<'a> CompoundBuilder<'a> {
    pub fn add_packet(mut self, packet: impl Into<PacketBuilder<'a>>) -> Self {
        self.packets.push(packet.into());
        self
    }

    /// Calculates the size required to write this Receiver Report packet.
    ///
    /// Returns an error if:
    ///
    /// * A Packet is erroneous.
    /// * A Packet defined a padding
    ///   while it's not the last packet in the Compound.
    pub fn calculate_size(&self) -> Result<usize, RtcpWriteError> {
        let mut size = 0;
        let last = self.packets.len().saturating_sub(1);
        for (idx, packet) in self.packets.iter().enumerate() {
            size += packet.calculate_size()?;

            if packet.get_padding() > 0 && idx != last {
                return Err(RtcpWriteError::NonLastCompoundPacketPadding);
            }
        }

        Ok(size)
    }

    /// Writes this Compound packet into `buf` without any validity checks.
    ///
    /// Uses the length of the buffer for the length field.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Panic
    ///
    /// Panics if the buf is not large enough.
    pub fn write_into_unchecked(mut self, buf: &mut [u8]) -> usize {
        let mut offset = 0;
        for packet in self.packets.drain(..) {
            offset += packet.write_into_unchecked(&mut buf[offset..]);
        }

        offset
    }

    /// Writes this Compound packet into `buf`.
    ///
    /// On success returns the number of bytes written or an
    /// `RtpWriteError` on failure.
    pub fn write_into(mut self, buf: &mut [u8]) -> Result<usize, RtcpWriteError> {
        let mut total_size = 0;
        let mut offset = 0;
        for packet in self.packets.drain(..) {
            let req_size = packet.calculate_size()?;
            total_size += req_size;

            if buf.len() < total_size {
                return Err(RtcpWriteError::OutputTooSmall(total_size));
            }

            offset += packet.write_into_unchecked(&mut buf[offset..offset + req_size]);
        }

        Ok(offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{App, Bye, ReceiverReport, SenderReport};

    #[test]
    fn parse_rr_bye() {
        let data = [
            0x80, 0xc9, 0x00, 0x01, 0x91, 0x82, 0x73, 0x64, 0x80, 0xcb, 0x00, 0x00,
        ];
        let mut compound = Compound::parse(&data).unwrap();
        let packet = compound.next().unwrap();
        matches!(packet, Packet::Rr(_));

        let packet = compound.next().unwrap();
        matches!(packet, Packet::Bye(_));

        assert!(compound.next().is_none());
    }

    #[test]
    fn build_rr_bye() {
        const REQ_LEN: usize = ReceiverReport::MIN_PACKET_LEN + Bye::MIN_PACKET_LEN;

        let b = Compound::builder()
            .add_packet(ReceiverReport::builder(0x1234567))
            .add_packet(Bye::builder());

        let mut data = [0; REQ_LEN];
        let len = b.write_into(&mut data).unwrap();
        assert_eq!(len, REQ_LEN);
        assert_eq!(
            data,
            [0x80, 0xc9, 0x00, 0x01, 0x01, 0x23, 0x45, 0x67, 0x80, 0xcb, 0x00, 0x00]
        );
    }

    #[test]
    fn parse_sr_bye() {
        let data = [
            0x82, 0xc8, 0x00, 0x06, 0x91, 0x82, 0x73, 0x64, 0x89, 0xab, 0xcd, 0xef, 0x02, 0x24,
            0x46, 0x68, 0x8a, 0xac, 0xce, 0xe0, 0xf1, 0xe2, 0xd3, 0xc4, 0xb5, 0xa6, 0x97, 0x88,
            0x80, 0xcb, 0x00, 0x00,
        ];
        let mut compound = Compound::parse(&data).unwrap();
        let packet = compound.next().unwrap();
        matches!(packet, Packet::Sr(_));

        let packet = compound.next().unwrap();
        matches!(packet, Packet::Bye(_));

        assert!(compound.next().is_none());
    }

    #[test]
    fn build_sr_bye() {
        const REQ_LEN: usize = SenderReport::MIN_PACKET_LEN + Bye::MIN_PACKET_LEN;

        let b = Compound::builder()
            .add_packet(SenderReport::builder(0x1234567))
            .add_packet(Bye::builder());

        let mut data = [0; REQ_LEN];
        let len = b.write_into(&mut data).unwrap();
        assert_eq!(len, REQ_LEN);
        assert_eq!(
            data,
            [
                0x80, 0xc8, 0x00, 0x06, 0x01, 0x23, 0x45, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x80, 0xcb, 0x00, 0x00,
            ]
        );
    }

    #[test]
    fn build_rr_bye_padding() {
        const REQ_LEN: usize = ReceiverReport::MIN_PACKET_LEN + Bye::MIN_PACKET_LEN + 4;

        let b = Compound::builder()
            .add_packet(ReceiverReport::builder(0x1234567))
            .add_packet(Bye::builder().padding(4));

        let mut data = [0; REQ_LEN];
        let len = b.write_into(&mut data).unwrap();
        assert_eq!(len, REQ_LEN);
        assert_eq!(
            data,
            [
                0x80, 0xc9, 0x00, 0x01, 0x01, 0x23, 0x45, 0x67, 0xa0, 0xcb, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x04,
            ]
        );
    }

    #[test]
    fn build_app_padding_bye() {
        let b = Compound::builder()
            .add_packet(App::builder(0x91827364, "name").padding(4))
            .add_packet(Bye::builder());

        let err = b.calculate_size().unwrap_err();
        assert_eq!(err, RtcpWriteError::NonLastCompoundPacketPadding);
    }
}
