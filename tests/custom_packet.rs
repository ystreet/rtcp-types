use rtcp_types::{
    prelude::*,
    utils::{parser, writer},
    Packet, RtcpPacket, RtcpParseError, RtcpWriteError, Unknown,
};

/// A Parsed Custom packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Custom<'a> {
    data: &'a [u8],
}

impl<'a> RtcpPacket for Custom<'a> {
    const MIN_PACKET_LEN: usize = 12;
    const PACKET_TYPE: u8 = 242;
}

impl<'a> RtcpPacketParser<'a> for Custom<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        parser::check_packet::<Self>(data)?;

        if data.len() < Self::PACKET_LEN {
            return Err(RtcpParseError::Truncated {
                expected: Self::PACKET_LEN,
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

impl<'a> Custom<'a> {
    pub const PACKET_LEN: usize = Custom::MIN_PACKET_LEN;
    pub const PAYLOAD_LEN: usize = 4;

    pub fn padding(&self) -> Option<u8> {
        parser::parse_padding(self.data)
    }

    pub fn ssrc(&self) -> u32 {
        parser::parse_ssrc(self.data)
    }

    pub fn payload(&self) -> &[u8; Custom::PAYLOAD_LEN] {
        self.data[8..8 + Custom::PAYLOAD_LEN].try_into().unwrap()
    }

    pub fn builder(ssrc: u32) -> CustomBuilder {
        CustomBuilder::new(ssrc)
    }
}

/// Custom packet Builder
#[derive(Debug)]
#[must_use = "The builder must be built to be used"]
pub struct CustomBuilder {
    ssrc: u32,
    padding: u8,
    payload: [u8; Custom::PAYLOAD_LEN],
}

impl CustomBuilder {
    fn new(ssrc: u32) -> Self {
        CustomBuilder {
            ssrc,
            padding: 0,
            payload: [0; Custom::PAYLOAD_LEN],
        }
    }

    /// Sets the number of padding bytes to use for this Custom.
    pub fn padding(mut self, padding: u8) -> Self {
        self.padding = padding;
        self
    }

    pub fn payload(mut self, payload: [u8; Custom::PAYLOAD_LEN]) -> Self {
        self.payload = payload;
        self
    }
}

impl RtcpPacketWriter for CustomBuilder {
    /// Calculates the size required to write this Custom packet.
    ///
    /// Returns an error if:
    ///
    /// * The padding is not a multiple of 4.
    #[inline]
    fn calculate_size(&self) -> Result<usize, RtcpWriteError> {
        writer::check_padding(self.padding)?;

        Ok(Custom::PACKET_LEN)
    }

    /// Writes this Custom packet specific data into `buf` without any validity checks.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Panic
    ///
    /// Panics if the buf is not large enough.
    #[inline]
    fn write_into_unchecked(&self, buf: &mut [u8]) -> usize {
        writer::write_header_unchecked::<Custom>(self.padding, 0, buf);

        buf[4..8].copy_from_slice(&self.ssrc.to_be_bytes());
        buf[8..12].copy_from_slice(&self.payload);

        let mut end = 12;
        end += writer::write_padding_unchecked(self.padding, &mut buf[end..]);

        end
    }

    fn get_padding(&self) -> Option<u8> {
        if self.padding == 0 {
            return None;
        }

        Some(self.padding)
    }
}

impl<'a> TryFrom<&'a Unknown<'a>> for Custom<'a> {
    type Error = RtcpParseError;

    fn try_from(u: &'a Unknown<'a>) -> Result<Self, Self::Error> {
        Custom::parse(u.data())
    }
}

impl<'a> TryFrom<&'a Packet<'a>> for Custom<'a> {
    type Error = RtcpParseError;

    fn try_from(p: &'a Packet<'a>) -> Result<Self, Self::Error> {
        match p {
            Packet::Unknown(p) => Self::try_from(p),
            _ => Err(RtcpParseError::PacketTypeMismatch {
                actual: p.type_(),
                requested: Custom::PACKET_TYPE,
            }),
        }
    }
}

#[test]
fn test_parse() {
    let data = [
        0x80, 0xf2, 0x00, 0x02, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00,
    ];
    let custom = Custom::parse(&data).unwrap();
    assert_eq!(custom.ssrc(), 0x12345678);
}

#[test]
fn test_build() {
    let b = Custom::builder(0x12345678).payload([0x01, 0x02, 0x03, 0x04]);

    let req_len = b.calculate_size().unwrap();
    assert_eq!(req_len, Custom::PACKET_LEN);
    let mut data = [0; Custom::PACKET_LEN];

    let len = b.write_into(&mut data).unwrap();
    assert_eq!(len, Custom::PACKET_LEN);

    assert_eq!(
        data,
        [0x80, 0xf2, 0x00, 0x02, 0x12, 0x34, 0x56, 0x78, 0x01, 0x02, 0x03, 0x04]
    );
}

#[test]
fn test_parse_generic_packet() {
    let data = [
        0x80, 0xf2, 0x00, 0x02, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00,
    ];
    let p = Packet::parse(&data).unwrap();
    assert!(p.is_unknown());
    assert_eq!(p.type_(), Custom::PACKET_TYPE);

    let custom = p.try_as::<Custom>().unwrap();
    assert_eq!(custom.ssrc(), 0x12345678);

    let Packet::Unknown(unknown) = p else {
        unreachable!()
    };
    let custom = unknown.try_as::<Custom>().unwrap();
    assert_eq!(custom.ssrc(), 0x12345678);
}

#[test]
fn test_parse_compound() {
    use rtcp_types::{Compound, Packet, ReceiverReport};

    let data = [
        0x80, 0xc9, 0x00, 0x01, 0x01, 0x23, 0x45, 0x67, 0x80, 0xf2, 0x00, 0x02, 0x12, 0x34, 0x56,
        0x78, 0x01, 0x02, 0x03, 0x04,
    ];
    let mut compound = Compound::parse(&data).unwrap();
    let p = compound.next().unwrap().unwrap();
    assert_eq!(p.type_(), ReceiverReport::PACKET_TYPE);

    let p = compound.next().unwrap().unwrap();
    assert!(p.is_unknown());
    assert_eq!(p.type_(), Custom::PACKET_TYPE);

    let custom = p.try_as::<Custom>().unwrap();
    assert_eq!(custom.ssrc(), 0x12345678);

    let Packet::Unknown(unknown) = p else {
        unreachable!()
    };
    let custom = unknown.try_as::<Custom>().unwrap();
    assert_eq!(custom.ssrc(), 0x12345678);

    assert!(compound.next().is_none());
}

#[test]
fn test_build_compound() {
    use rtcp_types::{Compound, ReceiverReport};

    const REQ_LEN: usize = ReceiverReport::MIN_PACKET_LEN + Custom::PACKET_LEN;
    let b = Compound::builder()
        .add_packet(ReceiverReport::builder(0x1234567))
        .add_packet(Custom::builder(0x12345678).payload([0x01, 0x02, 0x03, 0x04]));

    let req_len = b.calculate_size().unwrap();
    assert_eq!(req_len, REQ_LEN);
    let mut data = [0; REQ_LEN];

    let len = b.write_into(&mut data).unwrap();
    assert_eq!(len, REQ_LEN);

    assert_eq!(
        data,
        [
            0x80, 0xc9, 0x00, 0x01, 0x01, 0x23, 0x45, 0x67, 0x80, 0xf2, 0x00, 0x02, 0x12, 0x34,
            0x56, 0x78, 0x01, 0x02, 0x03, 0x04
        ]
    );
}
