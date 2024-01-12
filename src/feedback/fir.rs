// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::HashMap;

use crate::feedback::FciFeedbackPacketType;
use crate::prelude::*;
use crate::utils::u32_from_be_bytes;
use crate::{RtcpParseError, RtcpWriteError};

/// An entry in a Full Intra Refresh
#[derive(Debug, PartialEq, Eq)]
pub struct FirEntry {
    ssrc: u32,
    sequence: u8,
}

impl FirEntry {
    fn new(ssrc: u32, sequence: u8) -> Self {
        Self { ssrc, sequence }
    }

    /// The SSRC for this FIR
    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// The sequence count of the request. Intended for deduplication.
    pub fn sequence(&self) -> u8 {
        self.sequence
    }
}

pub struct FirParserEntryIter<'a> {
    parser: &'a Fir<'a>,
    i: usize,
}

impl<'a> FirParserEntryIter<'a> {
    fn decode_entry(entry: &[u8]) -> FirEntry {
        FirEntry::new(u32_from_be_bytes(&entry[0..4]), entry[4])
    }
}

impl<'a> std::iter::Iterator for FirParserEntryIter<'a> {
    type Item = FirEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let idx = self.i * 8;
        if idx + 7 >= self.parser.data.len() {
            return None;
        }
        let entry = FirParserEntryIter::decode_entry(&self.parser.data[idx..]);
        self.i += 1;
        Some(entry)
    }
}

/// FIR (Full Intra Refresh) information as specified in RFC 5104
pub struct Fir<'a> {
    data: &'a [u8],
}

impl<'a> Fir<'a> {
    /// The list of RTP SSRCs that are requesting a Full Intra Refresh.
    pub fn entries(&self) -> impl Iterator<Item = FirEntry> + '_ {
        FirParserEntryIter { parser: self, i: 0 }
    }

    /// Create a new [`FirBuilder`]
    pub fn builder() -> FirBuilder {
        FirBuilder::default()
    }
}

impl<'a> FciParser<'a> for Fir<'a> {
    const PACKET_TYPE: FciFeedbackPacketType = FciFeedbackPacketType::PAYLOAD;
    const FCI_FORMAT: u8 = 4;

    fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        if data.len() < 8 {
            return Err(RtcpParseError::Truncated {
                expected: 8,
                actual: data.len(),
            });
        }
        Ok(Self { data })
    }
}

/// Builder for a Full Intra Refresh packet
#[derive(Debug, Default)]
pub struct FirBuilder {
    ssrc_seq: HashMap<u32, u8>,
}

impl FirBuilder {
    /// Add an SSRC to this FIR packet.  An existing SSRC will have their sequence number updated.
    pub fn add_ssrc(mut self, ssrc: u32, sequence: u8) -> Self {
        self.ssrc_seq
            .entry(ssrc)
            .and_modify(|entry| {
                *entry = sequence;
            })
            .or_insert(sequence);
        self
    }
}

impl<'a> FciBuilder<'a> for FirBuilder {
    fn format(&self) -> u8 {
        Fir::FCI_FORMAT
    }

    fn supports_feedback_type(&self) -> FciFeedbackPacketType {
        Fir::PACKET_TYPE
    }
}

impl RtcpPacketWriter for FirBuilder {
    fn calculate_size(&self) -> Result<usize, RtcpWriteError> {
        let entries = self.ssrc_seq.len();
        if entries > u16::MAX as usize / 2 - 2 {
            return Err(RtcpWriteError::TooManyFir);
        }
        Ok(entries * 2 * 4)
    }

    fn write_into_unchecked(&self, buf: &mut [u8]) -> usize {
        let mut idx = 0;
        let mut end = idx;

        for (ssrc, sequence) in self.ssrc_seq.iter() {
            end += 4;
            buf[idx..end].copy_from_slice(&ssrc.to_be_bytes());
            idx = end;
            end += 4;
            buf[idx..end].copy_from_slice(&[*sequence, 0, 0, 0]);
            idx = end;
        }
        end
    }

    fn get_padding(&self) -> Option<u8> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PayloadFeedback;

    #[test]
    fn fir_build_parse() {
        const REQ_LEN: usize = PayloadFeedback::MIN_PACKET_LEN + 8;
        let mut data = [0; REQ_LEN];
        let fir = {
            let fci = Fir::builder().add_ssrc(0xfedcba98, 0x30);
            PayloadFeedback::builder_owned(fci)
                .sender_ssrc(0x98765432)
                .media_ssrc(0)
        };
        assert_eq!(fir.calculate_size().unwrap(), REQ_LEN);
        let len = fir.write_into(&mut data).unwrap();
        assert_eq!(len, REQ_LEN);
        assert_eq!(
            data,
            [
                0x84, 0xce, 0x00, 0x04, 0x98, 0x76, 0x54, 0x32, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xdc,
                0xba, 0x98, 0x30, 0x00, 0x00, 0x00
            ]
        );

        let fb = PayloadFeedback::parse(&data).unwrap();

        assert_eq!(fb.sender_ssrc(), 0x98765432);
        assert_eq!(fb.media_ssrc(), 0);
        let fir = fb.parse_fci::<Fir>().unwrap();
        let mut entry_iter = fir.entries();
        assert_eq!(entry_iter.next(), Some(FirEntry::new(0xfedcba98, 0x30)));
        assert_eq!(entry_iter.next(), None);
    }
}
