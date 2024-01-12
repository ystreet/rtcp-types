// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::feedback::FciFeedbackPacketType;
use crate::{prelude::*, RtcpParseError, RtcpWriteError};

/// Picture Loss Information as specified in RFC 4585
#[derive(Debug)]
pub struct Pli<'a> {
    _data: &'a [u8],
}

impl<'a> Pli<'a> {
    pub fn builder() -> PliBuilder {
        PliBuilder {}
    }
}

impl<'a> FciParser<'a> for Pli<'a> {
    const PACKET_TYPE: FciFeedbackPacketType = FciFeedbackPacketType::PAYLOAD;
    const FCI_FORMAT: u8 = 1;

    fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        if !data.is_empty() {
            return Err(RtcpParseError::TooLarge {
                expected: 0,
                actual: data.len(),
            });
        }
        Ok(Self { _data: data })
    }
}

/// Builder for Picture Loss Information
#[derive(Debug)]
pub struct PliBuilder {}

impl<'a> FciBuilder<'a> for PliBuilder {
    fn format(&self) -> u8 {
        1
    }

    fn supports_feedback_type(&self) -> FciFeedbackPacketType {
        FciFeedbackPacketType::PAYLOAD
    }
}

impl RtcpPacketWriter for PliBuilder {
    fn calculate_size(&self) -> Result<usize, RtcpWriteError> {
        Ok(0)
    }

    fn write_into_unchecked(&self, _buf: &mut [u8]) -> usize {
        0
    }

    fn get_padding(&self) -> Option<u8> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feedback::{PayloadFeedback, TransportFeedback};

    #[test]
    fn pli_build_parse() {
        const REQ_LEN: usize = PayloadFeedback::MIN_PACKET_LEN;
        let mut data = [0; REQ_LEN];
        let pli = {
            let fci = Pli::builder();
            PayloadFeedback::builder_owned(fci)
                .sender_ssrc(0x98765432)
                .media_ssrc(0x10fedcba)
        };
        assert_eq!(pli.calculate_size().unwrap(), REQ_LEN);
        let len = pli.write_into(&mut data).unwrap();
        assert_eq!(len, REQ_LEN);
        assert_eq!(
            data,
            [0x81, 0xce, 0x00, 0x02, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba,]
        );

        let fb = PayloadFeedback::parse(&data).unwrap();

        assert_eq!(fb.sender_ssrc(), 0x98765432);
        assert_eq!(fb.media_ssrc(), 0x10fedcba);
        let _pli = fb.parse_fci::<Pli>().unwrap();
    }

    #[test]
    fn pli_build_ref() {
        const REQ_LEN: usize = PayloadFeedback::MIN_PACKET_LEN;
        let mut data = [0; REQ_LEN];
        let fci = Pli::builder();
        let pli = PayloadFeedback::builder(&fci)
            .sender_ssrc(0x98765432)
            .media_ssrc(0x10fedcba);
        assert_eq!(pli.calculate_size().unwrap(), REQ_LEN);
        let len = pli.write_into(&mut data).unwrap();
        assert_eq!(len, REQ_LEN);
        assert_eq!(
            data,
            [0x81, 0xce, 0x00, 0x02, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba,]
        );
    }

    #[test]
    fn pli_parse_wrong_packet() {
        let fb = TransportFeedback::parse(&[
            0x81, 0xcd, 0x00, 0x02, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba,
        ])
        .unwrap();
        assert!(matches!(
            fb.parse_fci::<Pli>(),
            Err(RtcpParseError::WrongImplementation),
        ));
    }

    #[test]
    fn pli_build_wrong_packet_type() {
        const REQ_LEN: usize = TransportFeedback::MIN_PACKET_LEN;
        let mut data = [0; REQ_LEN];
        let fci = Pli::builder();
        let pli = TransportFeedback::builder(&fci)
            .sender_ssrc(0x98765432)
            .media_ssrc(0x10fedcba);
        assert!(matches!(
            pli.calculate_size(),
            Err(RtcpWriteError::FciWrongFeedbackPacketType)
        ));
        assert!(matches!(
            pli.write_into(&mut data),
            Err(RtcpWriteError::FciWrongFeedbackPacketType)
        ));
    }

    #[test]
    fn pli_parse_with_data() {
        let pli = PayloadFeedback::parse(&[
            0x81, 0xce, 0x00, 0x03, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x00, 0x00,
            0x00, 0x00,
        ])
        .unwrap();
        assert!(matches!(
            pli.parse_fci::<Pli>(),
            Err(RtcpParseError::TooLarge {
                expected: 0,
                actual: 4
            })
        ));
    }
}
