// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    prelude::*,
    utils::{pad_to_4bytes, parser, u32_from_be_bytes, writer},
    RtcpPacket, RtcpPacketParser, RtcpPacketWriter, RtcpParseError, RtcpWriteError,
};

/// A Parsed Bye packet.
#[derive(Debug, PartialEq, Eq)]
pub struct Bye<'a> {
    data: &'a [u8],
}

impl<'a> RtcpPacket for Bye<'a> {
    const MIN_PACKET_LEN: usize = 4;
    const PACKET_TYPE: u8 = 203;
}

impl<'a> RtcpPacketParser<'a> for Bye<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        parser::check_packet::<Self>(data)?;

        let reason_len_offset = Self::MIN_PACKET_LEN + 4 * parser::parse_count(data) as usize;
        if reason_len_offset > data.len() {
            return Err(RtcpParseError::Truncated {
                expected: reason_len_offset,
                actual: data.len(),
            });
        }

        if reason_len_offset < data.len() {
            let reason_len = data[reason_len_offset] as usize;
            if reason_len_offset + 1 + reason_len > data.len() {
                return Err(RtcpParseError::Truncated {
                    expected: reason_len_offset + 1 + reason_len,
                    actual: data.len(),
                });
            }
        } // else no reason in this packet

        Ok(Self { data })
    }

    #[inline(always)]
    fn header_data(&self) -> [u8; 4] {
        self.data[..4].try_into().unwrap()
    }
}

impl<'a> Bye<'a> {
    const MAX_SOURCES: u8 = Self::MAX_COUNT;
    const MAX_REASON_LEN: u8 = 0xff;

    pub fn padding(&self) -> Option<u8> {
        parser::parse_padding(self.data)
    }

    pub fn ssrcs(&self) -> impl Iterator<Item = u32> + '_ {
        self.data[4..4 + self.count() as usize * 4]
            .chunks_exact(4)
            .map(u32_from_be_bytes)
    }

    pub fn reason(&self) -> Option<&[u8]> {
        let offset = self.count() as usize * 4 + 4;
        let reason_aligned_len = self
            .length()
            .checked_sub(offset + 1 + self.padding().unwrap_or(0) as usize)?;

        if reason_aligned_len == 0 {
            return None;
        }

        let end = offset + 1 + self.data[offset] as usize;
        Some(&self.data[offset + 1..end])
    }

    pub fn get_reason_string(&self) -> Option<Result<String, std::string::FromUtf8Error>> {
        self.reason().map(|r| String::from_utf8(r.into()))
    }

    pub fn builder() -> ByeBuilder<'a> {
        ByeBuilder::new()
    }
}

/// Bye packet Builder
#[derive(Debug)]
pub struct ByeBuilder<'a> {
    padding: u8,
    sources: Vec<u32>,
    reason: &'a str,
}

impl<'a> ByeBuilder<'a> {
    fn new() -> Self {
        ByeBuilder {
            padding: 0,
            sources: Vec::with_capacity(Bye::MAX_SOURCES as usize),
            reason: "",
        }
    }

    /// Sets the number of padding bytes to use for this Bye packet.
    pub fn padding(mut self, padding: u8) -> Self {
        self.padding = padding;
        self
    }

    /// Attempts to add the provided Source.
    pub fn add_source(mut self, source: u32) -> Self {
        self.sources.push(source);
        self
    }

    /// Sets the reason for this Bye packet.
    pub fn reason(mut self, reason: &'a str) -> Self {
        self.reason = reason;
        self
    }
}

impl<'a> RtcpPacketWriter for ByeBuilder<'a> {
    /// Calculates the size required to write this Bye packet.
    ///
    /// Returns an error if:
    ///
    /// * Too many sources where added.
    /// * The length of the reason is out of range.
    /// * The padding is not a multiple of 4.
    fn calculate_size(&self) -> Result<usize, RtcpWriteError> {
        if self.sources.len() > Bye::MAX_SOURCES as usize {
            return Err(RtcpWriteError::TooManySources {
                count: self.sources.len(),
                max: Bye::MAX_SOURCES,
            });
        }

        writer::check_padding(self.padding)?;

        let mut size = Bye::MIN_PACKET_LEN + 4 * self.sources.len() + self.padding as usize;

        if !self.reason.is_empty() {
            let reason_len = self.reason.as_bytes().len();
            if reason_len > Bye::MAX_REASON_LEN as usize {
                return Err(RtcpWriteError::ReasonLenTooLarge {
                    len: reason_len,
                    max: Bye::MAX_REASON_LEN,
                });
            }

            // reason length + data
            size += 1 + reason_len;
            // 32bit packet alignment
            size = pad_to_4bytes(size);
        }

        Ok(size)
    }

    /// Write this Bye packet data into `buf` without any validity checks.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Panic
    ///
    /// Panics if the buf is not large enough.
    #[inline]
    fn write_into_unchecked(&self, buf: &mut [u8]) -> usize {
        let mut idx =
            writer::write_header_unchecked::<Bye>(self.padding, self.sources.len() as u8, buf);

        let mut end = idx;
        for ssrc in self.sources.iter() {
            end += 4;
            buf[idx..end].copy_from_slice(&ssrc.to_be_bytes());
            idx = end;
        }

        if !self.reason.is_empty() {
            let reason = self.reason.as_bytes();
            let reason_len = reason.len();

            buf[idx] = reason_len as u8;
            idx += 1;
            end = idx + reason_len;
            buf[idx..end].copy_from_slice(reason);
            idx = end;
            // 32bit packet alignmant
            end = pad_to_4bytes(end);
            if end > idx {
                buf[idx..end].fill(0);
            }
        }

        end += writer::write_padding_unchecked(self.padding, &mut buf[idx..]);

        end
    }

    fn get_padding(&self) -> Option<u8> {
        if self.padding == 0 {
            return None;
        }

        Some(self.padding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bye_empty() {
        let bye = Bye::parse(&[0x80, 0xcb, 0x00, 0x00]).unwrap();
        assert_eq!(bye.padding(), None);
        assert_eq!(bye.count(), 0);
        assert_eq!(bye.ssrcs().count(), 0);
        assert!(bye.reason().is_none());
        assert!(bye.get_reason_string().is_none());
    }

    #[test]
    fn build_bye_empty() {
        const REQ_LEN: usize = Bye::MIN_PACKET_LEN;
        let byeb = Bye::builder();
        let req_len = byeb.calculate_size().unwrap();
        assert_eq!(req_len, REQ_LEN);

        let mut data = [0; REQ_LEN];
        let len = byeb.write_into(&mut data).unwrap();
        assert_eq!(len, REQ_LEN);
        assert_eq!(data, [0x80, 0xcb, 0x00, 0x00]);
    }

    #[test]
    fn parse_bye_3_sources() {
        let bye = Bye::parse(&[
            0x83, 0xcb, 0x00, 0x03, 0x12, 0x34, 0x56, 0x78, 0x34, 0x56, 0x78, 0x9a, 0x56, 0x78,
            0x9a, 0xbc,
        ])
        .unwrap();
        assert_eq!(bye.padding(), None);
        assert_eq!(bye.count(), 3);

        let mut ssrc_iter = bye.ssrcs();
        assert_eq!(ssrc_iter.next(), Some(0x12345678));
        assert_eq!(ssrc_iter.next(), Some(0x3456789a));
        assert_eq!(ssrc_iter.next(), Some(0x56789abc));
        assert!(ssrc_iter.next().is_none());

        assert!(bye.reason().is_none());
        assert!(bye.get_reason_string().is_none());
    }

    #[test]
    fn build_bye_3_sources() {
        const REQ_LEN: usize = Bye::MIN_PACKET_LEN + 3 * 4;
        let byeb = Bye::builder()
            .add_source(0x12345678)
            .add_source(0x3456789a)
            .add_source(0x56789abc);
        let req_len = byeb.calculate_size().unwrap();
        assert_eq!(req_len, REQ_LEN);

        let mut data = [0; REQ_LEN];
        let len = byeb.write_into(&mut data).unwrap();
        assert_eq!(len, REQ_LEN);
        assert_eq!(
            data,
            [
                0x83, 0xcb, 0x00, 0x03, 0x12, 0x34, 0x56, 0x78, 0x34, 0x56, 0x78, 0x9a, 0x56, 0x78,
                0x9a, 0xbc,
            ]
        );
    }

    #[test]
    fn parse_bye_2_sources_reason() {
        let bye = Bye::parse(&[
            0x82, 0xcb, 0x00, 0x05, 0x12, 0x34, 0x56, 0x78, 0x34, 0x56, 0x78, 0x9a, 0x08, 0x53,
            0x68, 0x75, 0x74, 0x64, 0x6f, 0x77, 0x6e, 0x00, 0x00, 0x00,
        ])
        .unwrap();
        assert_eq!(bye.padding(), None);
        assert_eq!(bye.count(), 2);

        let mut ssrc_iter = bye.ssrcs();
        assert_eq!(ssrc_iter.next(), Some(0x12345678));
        assert_eq!(ssrc_iter.next(), Some(0x3456789a));
        assert!(ssrc_iter.next().is_none());

        assert_eq!(String::from_utf8_lossy(bye.reason().unwrap()), "Shutdown");
    }

    #[test]
    fn build_bye_2_sources_reason() {
        const REASON: &str = "Shutdown";
        const LEN: usize = Bye::MIN_PACKET_LEN + 2 * 4 + 1 + REASON.len();
        // 32bit packet alignment
        const REQ_LEN: usize = pad_to_4bytes(LEN);
        let byeb = Bye::builder()
            .add_source(0x12345678)
            .add_source(0x3456789a)
            .reason(REASON);
        let req_len = byeb.calculate_size().unwrap();
        assert_eq!(req_len, REQ_LEN);

        let mut data = [0; REQ_LEN];
        let len = byeb.write_into(&mut data).unwrap();
        assert_eq!(len, REQ_LEN);
        assert_eq!(
            data,
            [
                0x82, 0xcb, 0x00, 0x05, 0x12, 0x34, 0x56, 0x78, 0x34, 0x56, 0x78, 0x9a, 0x08, 0x53,
                0x68, 0x75, 0x74, 0x64, 0x6f, 0x77, 0x6e, 0x00, 0x00, 0x00
            ]
        );
    }

    #[test]
    fn build_bye_2_sources_raw_reason() {
        const REASON: &str = "Shutdown";
        const LEN: usize = Bye::MIN_PACKET_LEN + 2 * 4 + 1 + REASON.len();
        // 32bit packet alignment
        const REQ_LEN: usize = pad_to_4bytes(LEN);
        let byeb = Bye::builder()
            .add_source(0x12345678)
            .add_source(0x3456789a)
            .reason(REASON);
        let req_len = byeb.calculate_size().unwrap();
        assert_eq!(req_len, REQ_LEN);

        let mut data = [0; REQ_LEN];
        let len = byeb.write_into(&mut data).unwrap();
        assert_eq!(len, REQ_LEN);
        assert_eq!(
            data,
            [
                0x82, 0xcb, 0x00, 0x05, 0x12, 0x34, 0x56, 0x78, 0x34, 0x56, 0x78, 0x9a, 0x08, 0x53,
                0x68, 0x75, 0x74, 0x64, 0x6f, 0x77, 0x6e, 0x00, 0x00, 0x00
            ]
        );
    }

    #[test]
    fn build_too_many_sources() {
        let mut b = Bye::builder();
        for _ in 0..Bye::MAX_SOURCES as usize + 1 {
            b = b.add_source(0)
        }
        let err = b.calculate_size().unwrap_err();
        assert_eq!(
            err,
            RtcpWriteError::TooManySources {
                count: Bye::MAX_SOURCES as usize + 1,
                max: Bye::MAX_SOURCES
            }
        );
    }

    #[test]
    fn build_reason_too_large() {
        let reason: String =
            String::from_utf8([b'a'; Bye::MAX_REASON_LEN as usize + 1].into()).unwrap();
        let b = Bye::builder().reason(&reason);
        let err = b.calculate_size().unwrap_err();
        assert_eq!(
            err,
            RtcpWriteError::ReasonLenTooLarge {
                len: Bye::MAX_REASON_LEN as usize + 1,
                max: Bye::MAX_REASON_LEN
            }
        );
    }

    #[test]
    fn build_padding_not_multiple_4() {
        let b = Bye::builder().padding(5);
        let err = b.calculate_size().unwrap_err();
        assert_eq!(err, RtcpWriteError::InvalidPadding { padding: 5 });
    }
}
