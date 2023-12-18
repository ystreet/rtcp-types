// SPDX-License-Identifier: MIT OR Apache-2.0

use std::borrow::Cow;

use crate::feedback::FciFeedbackPacketType;
use crate::utils::pad_to_4bytes;
use crate::{prelude::*, RtcpParseError, RtcpWriteError};

#[derive(Debug)]
pub struct Rpsi<'a> {
    data: &'a [u8],
}

impl<'a> Rpsi<'a> {
    pub fn builder() -> RpsiBuilder<'a> {
        RpsiBuilder::default()
    }

    pub fn payload_type(&self) -> u8 {
        self.data[1] & 0x7f
    }

    pub fn bit_string(&self) -> (&[u8], usize) {
        let padding_bytes = self.padding_bytes();
        let padding_bits = self.data[0] as usize - padding_bytes * 8;
        (&self.data[2..self.data.len() - padding_bytes], padding_bits)
    }

    fn padding_bytes(&self) -> usize {
        (self.data[0] / 8) as usize
    }
}

impl<'a> FciParser<'a> for Rpsi<'a> {
    const PACKET_TYPE: FciFeedbackPacketType = FciFeedbackPacketType::PAYLOAD;
    const FCI_FORMAT: u8 = 3;

    fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        if data.len() < 4 {
            return Err(RtcpParseError::Truncated {
                expected: 4,
                actual: data.len(),
            });
        }
        let ret = Self { data };
        if ret.padding_bytes() > data.len() - 2 {
            return Err(RtcpParseError::Truncated {
                expected: ret.padding_bytes() + 2,
                actual: data.len(),
            });
        }

        Ok(ret)
    }
}

#[derive(Debug, Default)]
pub struct RpsiBuilder<'a> {
    payload_type: u8,
    native_bit_string: Cow<'a, [u8]>,
    native_bit_overrun: u8,
}

impl<'a> RpsiBuilder<'a> {
    pub fn payload_type(mut self, payload_type: u8) -> Self {
        self.payload_type = payload_type;
        self
    }

    pub fn native_data(mut self, data: impl Into<Cow<'a, [u8]>>, bit_overrun: u8) -> Self {
        self.native_bit_string = data.into();
        self.native_bit_overrun = bit_overrun;
        self
    }

    pub fn native_data_owned(
        self,
        data: impl Into<Cow<'a, [u8]>>,
        bit_overrun: u8,
    ) -> RpsiBuilder<'static> {
        RpsiBuilder {
            payload_type: self.payload_type,
            native_bit_string: data.into().into_owned().into(),
            native_bit_overrun: bit_overrun,
        }
    }
}

impl<'a> FciBuilder<'a> for RpsiBuilder<'a> {
    fn format(&self) -> u8 {
        Rpsi::FCI_FORMAT
    }

    fn supports_feedback_type(&self) -> FciFeedbackPacketType {
        FciFeedbackPacketType::PAYLOAD
    }
}

impl<'a> RtcpPacketWriter for RpsiBuilder<'a> {
    fn calculate_size(&self) -> Result<usize, RtcpWriteError> {
        if self.payload_type > 127 {
            return Err(RtcpWriteError::PayloadTypeInvalid);
        }
        if self.native_bit_overrun > 8
            || self.native_bit_string.is_empty() && self.native_bit_overrun > 0
        {
            return Err(RtcpWriteError::PaddingBitsTooLarge);
        }
        Ok(pad_to_4bytes(self.native_bit_string.len()))
    }

    fn write_into_unchecked(&self, buf: &mut [u8]) -> usize {
        let end = pad_to_4bytes(2 + self.native_bit_string.len());
        let trailing_bits =
            8 * (end - self.native_bit_string.len() - 2) + self.native_bit_overrun as usize;
        buf[0] = trailing_bits as u8;
        buf[1] = self.payload_type;
        let mut idx = 2 + self.native_bit_string.len();
        buf[2..idx].copy_from_slice(&self.native_bit_string);
        if !self.native_bit_string.is_empty() {
            let mut bitmask = 0;
            let mut trailing_bits = self.native_bit_overrun;
            while trailing_bits > 0 {
                bitmask = (bitmask << 1) | 1;
                trailing_bits -= 1;
            }
            buf[idx - 1] &= !bitmask;
        }
        while idx < end {
            buf[idx] = 0;
            idx += 1;
        }
        idx
    }

    fn get_padding(&self) -> Option<u8> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feedback::PayloadFeedback;

    #[test]
    fn rpsi_build_parse() {
        const REQ_LEN: usize = PayloadFeedback::MIN_PACKET_LEN + 4;
        let mut data = [0; REQ_LEN];
        let rpsi = {
            let data = &[0xf0];
            let fci = Rpsi::builder()
                .payload_type(96)
                .native_data_owned(data.as_ref(), 4);
            PayloadFeedback::builder(fci)
                .sender_ssrc(0x98765432)
                .media_ssrc(0x10fedcba)
        };
        assert_eq!(rpsi.calculate_size().unwrap(), REQ_LEN);
        let len = rpsi.write_into(&mut data).unwrap();
        assert_eq!(len, REQ_LEN);
        assert_eq!(
            data,
            [
                0x83, 0xce, 0x00, 0x03, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x0c, 0x60,
                0xf0, 0x00
            ]
        );

        let fb = PayloadFeedback::parse(&data).unwrap();

        assert_eq!(fb.sender_ssrc(), 0x98765432);
        assert_eq!(fb.media_ssrc(), 0x10fedcba);
        let rpsi = fb.parse_fci::<Rpsi>().unwrap();
        assert_eq!(rpsi.payload_type(), 96);
        assert_eq!(rpsi.bit_string(), ([0xf0].as_ref(), 4));
    }
}
