// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    prelude::*,
    utils::{parser::*, writer::*},
    RtcpPacket, RtcpParseError, RtcpWriteError,
};

/// A (currently) unknown RTCP packet type.  Can also be used as a way to parse a custom RTCP packet
/// type.
#[derive(Debug, PartialEq, Eq)]
pub struct Unknown<'a> {
    data: &'a [u8],
}

impl<'a> RtcpPacket for Unknown<'a> {
    const MIN_PACKET_LEN: usize = 4;
    const PACKET_TYPE: u8 = 255; // Not used
}

impl<'a> RtcpPacketParser<'a> for Unknown<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
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

    #[inline(always)]
    fn header_data(&self) -> [u8; 4] {
        self.data[..4].try_into().unwrap()
    }
}

impl<'a> Unknown<'a> {
    /// The data of this RTCP packet
    pub fn data(&self) -> &[u8] {
        self.data
    }

    /// Try to parse this unknown RTCP packet as a different RTCP packet.  Can be used with an
    /// external implementation of [`RtcpPacket`] to parse a custom RTCP packet.
    pub fn try_as<P>(&'a self) -> Result<P, RtcpParseError>
    where
        P: RtcpPacket,
        P: TryFrom<&'a Self, Error = RtcpParseError>,
    {
        TryFrom::try_from(self)
    }

    /// The builder for an [`Unknown`] RTCP packet.  The data does not include the 4 byte RTCP
    /// header.
    pub fn builder(type_: u8, data: &'a [u8]) -> UnknownBuilder<'a> {
        UnknownBuilder::new(type_, data)
    }
}

/// Unknown RTCP packet builder
#[derive(Debug)]
#[must_use = "The builder must be built to be used"]
pub struct UnknownBuilder<'a> {
    padding: u8,
    type_: u8,
    count: u8,
    data: &'a [u8],
}

impl<'a> UnknownBuilder<'a> {
    /// Create a new builder for an [`Unknown`] RTCP packet.  The data does not include the 4 byte RTCP
    /// header.
    pub fn new(type_: u8, data: &'a [u8]) -> UnknownBuilder<'a> {
        UnknownBuilder {
            padding: 0,
            type_,
            count: 0,
            data,
        }
    }

    /// Sets the number of padding bytes to use for this Unknown packet
    pub fn padding(mut self, padding: u8) -> Self {
        self.padding = padding;
        self
    }

    /// Set the count (or possibly type) field in the RTCP header.  The exact interpretation of
    /// this value is RTCP packet specific.
    pub fn count(mut self, count: u8) -> Self {
        self.count = count;
        self
    }
}

impl<'a> RtcpPacketWriter for UnknownBuilder<'a> {
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

    fn get_padding(&self) -> Option<u8> {
        if self.padding == 0 {
            return None;
        }

        Some(self.padding)
    }
}

/// A (closed) enum of all currently known RTCP packet types.  The Unknown variant can be used to
/// parse a custom RTCP packet.
#[derive(Debug)]
pub enum Packet<'a> {
    /// An [`App`](crate::App) packet.
    App(crate::App<'a>),
    /// A [`Bye`](crate::Bye) packet.
    Bye(crate::Bye<'a>),
    /// A [`ReceiverReport`](crate::ReceiverReport) packet.
    Rr(crate::ReceiverReport<'a>),
    /// A [`Sdes`](crate::Sdes) packet.
    Sdes(crate::Sdes<'a>),
    /// A [`SenderReport`](crate::SenderReport) packet.
    Sr(crate::SenderReport<'a>),
    /// A [`TransportFeedback`](crate::TransportFeedback) packet.
    TransportFeedback(crate::TransportFeedback<'a>),
    /// A [`PayloadFeedback`](crate::PayloadFeedback) packet.
    PayloadFeedback(crate::PayloadFeedback<'a>),
    /// An [`XR`](crate::Xr) packet.
    Xr(crate::Xr<'a>),
    /// An [`Unknown`](crate::Unknown) packet.
    Unknown(Unknown<'a>),
}

impl<'a> Packet<'a> {
    /// Whether the packet is of an unknown type.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Packet::Unknown(_))
    }
}

impl<'a> RtcpPacket for Packet<'a> {
    const MIN_PACKET_LEN: usize = 4;
    const PACKET_TYPE: u8 = 255; // Not used
}

impl<'a> RtcpPacketParser<'a> for Packet<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        if data.len() < Self::MIN_PACKET_LEN {
            return Err(RtcpParseError::Truncated {
                expected: Self::MIN_PACKET_LEN,
                actual: data.len(),
            });
        }

        match parse_packet_type(data) {
            crate::App::PACKET_TYPE => crate::App::parse(data).map(Packet::App),
            crate::Bye::PACKET_TYPE => crate::Bye::parse(data).map(Packet::Bye),
            crate::ReceiverReport::PACKET_TYPE => {
                crate::ReceiverReport::parse(data).map(Packet::Rr)
            }
            crate::Sdes::PACKET_TYPE => crate::Sdes::parse(data).map(Packet::Sdes),
            crate::SenderReport::PACKET_TYPE => crate::SenderReport::parse(data).map(Packet::Sr),
            crate::PayloadFeedback::PACKET_TYPE => {
                crate::PayloadFeedback::parse(data).map(Packet::PayloadFeedback)
            }
            crate::TransportFeedback::PACKET_TYPE => {
                crate::TransportFeedback::parse(data).map(Packet::TransportFeedback)
            }
            crate::Xr::PACKET_TYPE => crate::Xr::parse(data).map(Packet::Xr),
            _ => Ok(Packet::Unknown(Unknown::parse(data)?)),
        }
    }

    #[inline(always)]
    fn header_data(&self) -> [u8; 4] {
        use Packet::*;
        match self {
            App(this) => this.header_data(),
            Bye(this) => this.header_data(),
            Rr(this) => this.header_data(),
            Sdes(this) => this.header_data(),
            Sr(this) => this.header_data(),
            TransportFeedback(this) => this.header_data(),
            PayloadFeedback(this) => this.header_data(),
            Xr(this) => this.header_data(),
            Unknown(this) => this.header_data(),
        }
    }
}

impl<'a> Packet<'a> {
    /// Try parsing this [`Packet`] as a particular [`RtcpPacket`] implementation.
    pub fn try_as<P>(&'a self) -> Result<P, RtcpParseError>
    where
        P: RtcpPacket,
        P: TryFrom<&'a Self, Error = RtcpParseError>,
    {
        TryFrom::try_from(self)
    }
}

/// A compound RTCP packet consisting of multiple RTCP packets one after the other
#[derive(Debug)]
pub struct Compound<'a> {
    data: &'a [u8],
    offset: usize,
    is_over: bool,
}

impl<'a> Compound<'a> {
    /// Parse data into a [`Compound`] RTCP packet.
    ///
    /// This will validate that the length of each individual RTCP packet is valid upfront.
    pub fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        let mut offset = 0;
        let mut packet_length;

        if data.is_empty() {
            return Err(RtcpParseError::Truncated {
                expected: 4,
                actual: 0,
            });
        }

        while offset < data.len() {
            if data.len() < offset + Unknown::MIN_PACKET_LEN {
                return Err(RtcpParseError::Truncated {
                    expected: offset + Unknown::MIN_PACKET_LEN,
                    actual: data.len(),
                });
            }

            packet_length = parse_length(&data[offset..]);
            if data.len() < offset + packet_length {
                return Err(RtcpParseError::Truncated {
                    expected: offset + packet_length,
                    actual: data.len(),
                });
            }

            offset += packet_length;
        }

        Ok(Self {
            data,
            offset: 0,
            is_over: false,
        })
    }

    /// Create a new [`CompoundBuilder`]
    pub fn builder() -> CompoundBuilder<'a> {
        CompoundBuilder::default()
    }
}

impl<'a> Iterator for Compound<'a> {
    type Item = Result<Packet<'a>, RtcpParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_over {
            return None;
        }

        // Length conformity checked in `Self::parse`

        let packet_length = parse_length(&self.data[self.offset..]);
        let res = Packet::parse(&self.data[self.offset..self.offset + packet_length]);

        self.is_over = res.is_err();

        self.offset += packet_length;
        if self.offset >= self.data.len() {
            self.is_over = true;
        }

        Some(res)
    }
}

/// A builder for a RTCP packet
#[derive(Debug)]
#[must_use = "The builder must be built to be used"]
pub enum PacketBuilder<'a> {
    /// An [`App`](crate::AppBuilder) packet.
    App(crate::app::AppBuilder<'a>),
    /// A [`Bye`](crate::ByeBuilder) packet.
    Bye(crate::bye::ByeBuilder<'a>),
    /// A [`ReceiverReport`](crate::ReceiverReportBuilder) packet.
    Rr(crate::receiver::ReceiverReportBuilder),
    /// A [`Sdes`](crate::SdesBuilder) packet.
    Sdes(crate::sdes::SdesBuilder<'a>),
    /// A [`SenderReport`](crate::SenderReportBuilder) packet.
    Sr(crate::sender::SenderReportBuilder),
    /// A [`TransportFeedback`](crate::TransportFeedbackBuilder) packet.
    TransportFeedback(crate::feedback::TransportFeedbackBuilder<'a>),
    /// A [`PayloadFeedback`](crate::PayloadFeedbackBuilder) packet.
    PayloadFeedback(crate::feedback::PayloadFeedbackBuilder<'a>),
    /// An [`XR`](crate::XrBuilder) packet.
    Xr(crate::xr::XrBuilder),
    /// An [`Unknown`](crate::UnknownBuilder) packet.
    Unknown(UnknownBuilder<'a>),
}

impl<'a> RtcpPacketWriter for PacketBuilder<'a> {
    fn get_padding(&self) -> Option<u8> {
        use PacketBuilder::*;
        match self {
            App(this) => this.get_padding(),
            Bye(this) => this.get_padding(),
            Rr(this) => this.get_padding(),
            Sdes(this) => this.get_padding(),
            Sr(this) => this.get_padding(),
            TransportFeedback(this) => this.get_padding(),
            PayloadFeedback(this) => this.get_padding(),
            Xr(this) => this.get_padding(),
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
            TransportFeedback(this) => this.calculate_size(),
            PayloadFeedback(this) => this.calculate_size(),
            Xr(this) => this.calculate_size(),
            Unknown(this) => this.calculate_size(),
        }
    }

    fn write_into_unchecked(&self, buf: &mut [u8]) -> usize {
        use PacketBuilder::*;
        match self {
            App(this) => this.write_into_unchecked(buf),
            Bye(this) => this.write_into_unchecked(buf),
            Rr(this) => this.write_into_unchecked(buf),
            Sdes(this) => this.write_into_unchecked(buf),
            Sr(this) => this.write_into_unchecked(buf),
            TransportFeedback(this) => this.write_into_unchecked(buf),
            PayloadFeedback(this) => this.write_into_unchecked(buf),
            Xr(this) => this.write_into_unchecked(buf),
            Unknown(this) => this.write_into_unchecked(buf),
        }
    }
}

/// A builder for a [`Compound`] RTCP packet
#[derive(Default, Debug)]
#[must_use = "The builder must be built to be used"]
pub struct CompoundBuilder<'a> {
    packets: Vec<Box<dyn RtcpPacketWriter + 'a>>,
}

impl<'a> CompoundBuilder<'a> {
    /// Add a packet to the compound rtcp packet
    pub fn add_packet(mut self, packet: impl RtcpPacketWriter + 'a) -> Self {
        self.packets.push(Box::new(packet));
        self
    }
}

impl<'a> RtcpPacketWriter for CompoundBuilder<'a> {
    /// Calculates the size required to write this Receiver Report packet.
    ///
    /// Returns an error if:
    ///
    /// * A Packet is erroneous.
    /// * A Packet defined a padding
    ///   while it's not the last packet in the Compound.
    fn calculate_size(&self) -> Result<usize, RtcpWriteError> {
        let mut size = 0;
        let last = self.packets.len().saturating_sub(1);
        for (idx, packet) in self.packets.iter().enumerate() {
            size += packet.calculate_size()?;

            if packet.get_padding().unwrap_or(0) > 0 && idx != last {
                return Err(RtcpWriteError::NonLastCompoundPacketPadding);
            }
        }

        Ok(size)
    }

    /// Writes this Compound packet into `buf` without prior length checks.
    ///
    /// Uses the length of the buffer for the length field.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Panic
    ///
    /// Panics if the buf is not large enough or if a packet is invalid.
    fn write_into_unchecked(&self, buf: &mut [u8]) -> usize {
        let mut offset = 0;
        for packet in self.packets.iter() {
            let req_size = packet.calculate_size().unwrap();
            offset += packet.write_into_unchecked(&mut buf[offset..offset + req_size]);
        }

        offset
    }

    fn get_padding(&self) -> Option<u8> {
        self.packets.last()?.get_padding()
    }
}

macro_rules! impl_try_from {
    ($parser:ty, $builder:ty, $variant:ident) => {
        impl<'a> TryFrom<Unknown<'a>> for $parser {
            type Error = RtcpParseError;

            fn try_from(p: Unknown<'a>) -> Result<Self, Self::Error> {
                <$parser>::parse(p.data)
            }
        }

        impl<'a> TryFrom<&'a Unknown<'a>> for $parser {
            type Error = RtcpParseError;

            fn try_from(p: &'a Unknown<'a>) -> Result<Self, Self::Error> {
                <$parser>::parse(p.data)
            }
        }

        impl<'a> TryFrom<Packet<'a>> for $parser {
            type Error = RtcpParseError;

            fn try_from(p: Packet<'a>) -> Result<Self, Self::Error> {
                match p {
                    Packet::$variant(this) => Ok(this),
                    Packet::Unknown(p) => Self::try_from(p),
                    _ => Err(RtcpParseError::PacketTypeMismatch {
                        actual: p.type_(),
                        requested: <$parser>::PACKET_TYPE,
                    }),
                }
            }
        }

        impl<'a> TryFrom<&'a Packet<'a>> for $parser {
            type Error = RtcpParseError;

            fn try_from(p: &'a Packet<'a>) -> Result<Self, Self::Error> {
                match p {
                    Packet::$variant(this) => Ok(this.clone()),
                    Packet::Unknown(p) => Self::try_from(p),
                    _ => Err(RtcpParseError::PacketTypeMismatch {
                        actual: p.type_(),
                        requested: <$parser>::PACKET_TYPE,
                    }),
                }
            }
        }

        impl<'a> From<$parser> for Packet<'a> {
            fn from(p: $parser) -> Self {
                Packet::$variant(p)
            }
        }

        impl<'a> From<$builder> for PacketBuilder<'a> {
            fn from(pb: $builder) -> Self {
                Self::$variant(pb)
            }
        }
    };
}

impl_try_from!(crate::app::App<'a>, crate::app::AppBuilder<'a>, App);
impl_try_from!(crate::bye::Bye<'a>, crate::bye::ByeBuilder<'a>, Bye);
impl_try_from!(crate::sdes::Sdes<'a>, crate::sdes::SdesBuilder<'a>, Sdes);
impl_try_from!(
    crate::receiver::ReceiverReport<'a>,
    crate::receiver::ReceiverReportBuilder,
    Rr
);
impl_try_from!(
    crate::sender::SenderReport<'a>,
    crate::sender::SenderReportBuilder,
    Sr
);
impl_try_from!(
    crate::feedback::TransportFeedback<'a>,
    crate::feedback::TransportFeedbackBuilder<'a>,
    TransportFeedback
);
impl_try_from!(
    crate::feedback::PayloadFeedback<'a>,
    crate::feedback::PayloadFeedbackBuilder<'a>,
    PayloadFeedback
);
impl_try_from!(crate::xr::Xr<'a>, crate::xr::XrBuilder, Xr);

impl<'a> From<Unknown<'a>> for Packet<'a> {
    fn from(p: Unknown<'a>) -> Self {
        Packet::Unknown(p)
    }
}

impl<'a> From<UnknownBuilder<'a>> for PacketBuilder<'a> {
    fn from(pb: UnknownBuilder<'a>) -> Self {
        Self::Unknown(pb)
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
        let packet = compound.next().unwrap().unwrap();
        matches!(packet, Packet::Rr(_));

        let packet = compound.next().unwrap().unwrap();
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
            0x80, 0xc8, 0x00, 0x06, 0x91, 0x82, 0x73, 0x64, 0x89, 0xab, 0xcd, 0xef, 0x02, 0x24,
            0x46, 0x68, 0x8a, 0xac, 0xce, 0xe0, 0xf1, 0xe2, 0xd3, 0xc4, 0xb5, 0xa6, 0x97, 0x88,
            0x80, 0xcb, 0x00, 0x00,
        ];
        let mut compound = Compound::parse(&data).unwrap();
        let packet = compound.next().unwrap().unwrap();
        matches!(packet, Packet::Sr(_));

        let packet = compound.next().unwrap().unwrap();
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
    fn parse_unknown() {
        let data = [
            0x80, 0xf2, 0x00, 0x02, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00,
        ];
        let p = Packet::parse(&data).unwrap();
        assert!(p.is_unknown());
        assert_eq!(p.type_(), 242);
    }

    #[test]
    fn build_app_padding_bye() {
        let b = Compound::builder()
            .add_packet(App::builder(0x91827364, "name").padding(4))
            .add_packet(Bye::builder());

        let err = b.calculate_size().unwrap_err();
        assert_eq!(err, RtcpWriteError::NonLastCompoundPacketPadding);
    }

    #[test]
    fn parse_rr_bye_wrong_first_len() {
        let data = [
            0x80, 0xc9, 0x00, 0x03, 0x91, 0x82, 0x73, 0x64, 0x80, 0xcb, 0x00, 0x00,
        ];
        let err = Compound::parse(&data).unwrap_err();
        assert_eq!(
            err,
            RtcpParseError::Truncated {
                expected: 16,
                actual: 12
            }
        );
    }

    #[test]
    fn parse_rr_truncated_bye() {
        let data = [
            0x80, 0xc9, 0x00, 0x01, 0x91, 0x82, 0x73, 0x64, 0x80, 0xcb, 0x00,
        ];
        let err = Compound::parse(&data).unwrap_err();
        assert_eq!(
            err,
            RtcpParseError::Truncated {
                expected: 12,
                actual: 11
            }
        );
    }

    #[test]
    fn parsing_failure_rr_bye() {
        let data = [
            0x81, 0xc9, 0x00, 0x01, 0x91, 0x82, 0x73, 0x64, 0x80, 0xcb, 0x00, 0x00,
        ];
        let mut compound = Compound::parse(&data).unwrap();

        // RR count is 1 when the actual packet contains no reports.
        let err = compound.next().unwrap().unwrap_err();
        assert_eq!(
            err,
            RtcpParseError::Truncated {
                expected: 32,
                actual: 8
            }
        );

        assert!(compound.next().is_none());
    }

    #[test]
    fn parse_packet_try_as_app() {
        let data = [
            0x80, 0xcc, 0x00, 0x02, 0x91, 0x82, 0x73, 0x64, 0x6e, 0x61, 0x6d, 0x65,
        ];
        let packet = Packet::parse(&data).unwrap();

        let app = packet.try_as::<crate::App>().unwrap();
        assert_eq!(app.name(), "name".as_bytes());

        matches!(packet, Packet::App(_));
    }

    #[test]
    fn parse_unknown_try_as_bye() {
        let data = [0x81, 0xcb, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78];
        let unknown = Unknown::parse(&data).unwrap();

        let bye = unknown.try_as::<crate::Bye>().unwrap();
        let mut ssrcs = bye.ssrcs();
        let ssrc = ssrcs.next().unwrap();
        assert_eq!(ssrc, 0x12345678);
    }
}
