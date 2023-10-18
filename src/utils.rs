// SPDX-License-Identifier: MIT OR Apache-2.0

#[track_caller]
#[inline(always)]
pub(crate) fn u16_from_be_bytes(bytes: &[u8]) -> u16 {
    u16::from_be_bytes(bytes.try_into().expect("expecting 2 bytes"))
}

#[track_caller]
#[inline(always)]
pub(crate) fn u32_from_be_bytes(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().expect("expecting 4 bytes"))
}

#[track_caller]
#[inline(always)]
pub(crate) fn u64_from_be_bytes(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().expect("expecting 8 bytes"))
}

#[inline(always)]
pub(crate) const fn pad_to_4bytes(num: usize) -> usize {
    (num + 3) & !3
}

#[inline(always)]
pub(crate) fn data_to_string(data: &[u8]) -> Result<String, std::string::FromUtf8Error> {
    String::from_utf8(Vec::from_iter(data.iter().map_while(|&b| {
        if b == 0 {
            None
        } else {
            Some(b)
        }
    })))
}

pub(crate) mod parser {
    use crate::{RtcpPacket, RtcpParseError};

    /// Performs checks common to every RTCP packets.
    ///
    /// Call this before parsing the specificities of the RTCP packet.
    #[inline(always)]
    pub fn check_packet<P: RtcpPacket>(packet: &[u8]) -> Result<(), RtcpParseError> {
        if packet.len() < P::MIN_PACKET_LEN {
            return Err(RtcpParseError::Truncated {
                expected: P::MIN_PACKET_LEN,
                actual: packet.len(),
            });
        }

        let version = parse_version(packet);
        if version != P::VERSION {
            return Err(RtcpParseError::UnsupportedVersion(version));
        }

        if parse_packet_type(packet) != P::PACKET_TYPE {
            return Err(RtcpParseError::WrongImplementation);
        }

        let length = parse_length(packet);
        if packet.len() < length {
            return Err(RtcpParseError::Truncated {
                expected: length,
                actual: packet.len(),
            });
        }

        if packet.len() > length {
            return Err(RtcpParseError::TooLarge {
                expected: length,
                actual: packet.len(),
            });
        }

        if let Some(padding) = parse_padding(packet) {
            if padding == 0 {
                return Err(RtcpParseError::InvalidPadding);
            }
        }

        Ok(())
    }

    #[inline(always)]
    pub(crate) fn parse_version(packet: &[u8]) -> u8 {
        packet[0] >> 6
    }

    #[inline(always)]
    pub(crate) fn parse_padding_bit(packet: &[u8]) -> bool {
        (packet[0] & 0x20) != 0
    }

    #[inline(always)]
    pub(crate) fn parse_padding(packet: &[u8]) -> Option<u8> {
        if parse_padding_bit(packet) {
            let length = parse_length(packet);
            Some(packet[length - 1])
        } else {
            None
        }
    }

    #[inline(always)]
    pub(crate) fn parse_count(packet: &[u8]) -> u8 {
        packet[0] & 0x1f
    }

    #[inline(always)]
    pub(crate) fn parse_packet_type(packet: &[u8]) -> u8 {
        packet[1]
    }

    #[inline(always)]
    pub(crate) fn parse_length(packet: &[u8]) -> usize {
        4 * (super::u16_from_be_bytes(&packet[2..4]) as usize + 1)
    }

    #[inline(always)]
    pub(crate) fn parse_ssrc(packet: &[u8]) -> u32 {
        super::u32_from_be_bytes(&packet[4..8])
    }
}
