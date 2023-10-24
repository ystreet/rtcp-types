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

pub mod parser {
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

    /// Parses the version from the provided packet data.
    #[inline(always)]
    pub fn parse_version(packet: &[u8]) -> u8 {
        packet[0] >> 6
    }

    /// Parses the padding bit from the provided packet data.
    #[inline(always)]
    pub fn parse_padding_bit(packet: &[u8]) -> bool {
        (packet[0] & 0x20) != 0
    }

    /// Parses the padding from the provided packet data.
    ///
    /// Returns the last byte of the packet if the padding bit is set
    /// otherwise returns `None`.
    #[inline(always)]
    pub fn parse_padding(packet: &[u8]) -> Option<u8> {
        if parse_padding_bit(packet) {
            let length = parse_length(packet);
            Some(packet[length - 1])
        } else {
            None
        }
    }

    /// Parses the count from the provided packet data.
    #[inline(always)]
    pub fn parse_count(packet: &[u8]) -> u8 {
        packet[0] & 0x1f
    }

    /// Parses the packet type from the provided packet data.
    #[inline(always)]
    pub fn parse_packet_type(packet: &[u8]) -> u8 {
        packet[1]
    }

    /// Parses the length from the provided packet data.
    #[inline(always)]
    pub fn parse_length(packet: &[u8]) -> usize {
        4 * (super::u16_from_be_bytes(&packet[2..4]) as usize + 1)
    }

    /// Parses the SSRC from the provided packet data.
    ///
    /// This is applicable for packets where SSRC is available at [4..8].
    #[inline(always)]
    pub fn parse_ssrc(packet: &[u8]) -> u32 {
        super::u32_from_be_bytes(&packet[4..8])
    }
}

pub mod writer {
    use crate::{RtcpPacket, RtcpWriteError};

    /// Checks that the provided padding is a mutliple of 4.
    #[inline(always)]
    pub fn check_padding(padding: u8) -> Result<(), RtcpWriteError> {
        if padding % 4 != 0 {
            return Err(RtcpWriteError::InvalidPadding { padding });
        }

        Ok(())
    }

    /// Writes the common header for this RTCP packet into `buf` without any validity checks.
    ///
    /// Uses the length of the buffer for the length field.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Panic
    ///
    /// Panics if the buf is not large enough.
    #[inline(always)]
    pub fn write_header_unchecked<P: RtcpPacket>(padding: u8, count: u8, buf: &mut [u8]) -> usize {
        buf[0] = P::VERSION << 6;
        if padding > 0 {
            buf[0] |= 0x20;
        }
        buf[0] |= count;
        buf[1] = P::PACKET_TYPE;
        let len = buf.len();
        buf[2..4].copy_from_slice(&((len / 4 - 1) as u16).to_be_bytes());

        4
    }

    /// Writes the padding for this RTCP packet into `buf` without any validity checks.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Panic
    ///
    /// Panics if the buf is not large enough.
    #[inline(always)]
    pub fn write_padding_unchecked(padding: u8, buf: &mut [u8]) -> usize {
        let mut end = 0;
        if padding > 0 {
            end += padding as usize;

            buf[0..end - 1].fill(0);
            buf[end - 1] = padding;
        }

        end
    }
}
