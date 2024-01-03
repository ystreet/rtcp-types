// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeSet;

use crate::feedback::FciFeedbackPacketType;
use crate::{prelude::*, utils::u16_from_be_bytes};
use crate::{RtcpParseError, RtcpWriteError};

pub struct NackParserEntryIter<'a> {
    parser: &'a Nack<'a>,
    i: usize,
    mask_i: usize,
}

impl<'a> NackParserEntryIter<'a> {
    fn decode_entry(entry: &[u8]) -> (u16, u16) {
        (
            u16_from_be_bytes(&entry[0..2]),
            u16_from_be_bytes(&entry[2..4]),
        )
    }
}

impl<'a> std::iter::Iterator for NackParserEntryIter<'a> {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.mask_i > 16 {
                self.mask_i = 0;
                self.i += 1;
            }
            let idx = self.i * 4;
            if idx + 3 >= self.parser.data.len() {
                return None;
            }
            let (base, mask) = NackParserEntryIter::decode_entry(&self.parser.data[idx..]);
            if self.mask_i == 0 {
                self.mask_i += 1;
                return Some(base);
            }

            loop {
                let mask = mask >> (self.mask_i - 1);
                if (mask & 0x1) > 0 {
                    self.mask_i += 1;
                    let ret = base.wrapping_add(self.mask_i as u16 - 1);
                    return Some(ret);
                }
                self.mask_i += 1;
                if self.mask_i > 16 {
                    break;
                }
            }
        }
    }
}

/// Generic NACK FCI information as specified in RFC 4585
pub struct Nack<'a> {
    data: &'a [u8],
}

impl<'a> Nack<'a> {
    /// The list of RTP sequence numbers that is being NACKed.
    pub fn entries(&self) -> impl Iterator<Item = u16> + '_ {
        NackParserEntryIter {
            parser: self,
            i: 0,
            mask_i: 0,
        }
    }

    pub fn builder() -> NackBuilder {
        NackBuilder::default()
    }
}

impl<'a> FciParser<'a> for Nack<'a> {
    const PACKET_TYPE: FciFeedbackPacketType = FciFeedbackPacketType::TRANSPORT;
    const FCI_FORMAT: u8 = 1;

    fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        Ok(Self { data })
    }
}

pub struct NackBuilderEntryIter<I: Iterator<Item = u16>> {
    i: usize,
    base_entry: Option<u16>,
    seq_iter: I,
    last_entry: u16,
}

fn encode_entry(base: u16, mask: u16) -> [u8; 4] {
    [
        ((base & 0xff00) >> 8) as u8,
        (base & 0xff) as u8,
        ((mask & 0xff00) >> 8) as u8,
        (mask & 0xff) as u8,
    ]
}

impl<I: Iterator<Item = u16>> std::iter::Iterator for NackBuilderEntryIter<I> {
    type Item = [u8; 4];

    fn next(&mut self) -> Option<Self::Item> {
        let mut bitmask = 0;
        for entry in self.seq_iter.by_ref() {
            self.last_entry = entry;
            if let Some(base) = self.base_entry {
                let diff = entry.wrapping_sub(base);
                if diff > 16 {
                    // bitmask will overflow next iteration, return the current value
                    let ret = encode_entry(base, bitmask);
                    self.base_entry = Some(entry);
                    return Some(ret);
                }
                if diff > 0 {
                    bitmask |= 1 << (diff - 1);
                }
                self.i += 1;
            } else {
                // initial set up for the first value
                self.base_entry = Some(entry);
                self.i += 1;
                continue;
            }
        }

        if let Some(base) = self.base_entry {
            // we need to output the final entry
            let ret = encode_entry(base, bitmask);
            self.base_entry = None;
            return Some(ret);
        }
        None
    }
}

#[derive(Debug, Default)]
pub struct NackBuilder {
    rtp_seq: BTreeSet<u16>,
}

impl NackBuilder {
    pub fn add_rtp_sequence(mut self, rtp_sequence: u16) -> Self {
        self.rtp_seq.insert(rtp_sequence);
        self
    }

    fn entries(&self) -> impl Iterator<Item = [u8; 4]> + '_ {
        NackBuilderEntryIter {
            i: 0,
            base_entry: None,
            seq_iter: self.rtp_seq.iter().copied(),
            last_entry: 0,
        }
    }
}

impl<'a> FciBuilder<'a> for NackBuilder {
    fn format(&self) -> u8 {
        1
    }

    fn supports_feedback_type(&self) -> FciFeedbackPacketType {
        FciFeedbackPacketType::TRANSPORT
    }
}

impl RtcpPacketWriter for NackBuilder {
    fn calculate_size(&self) -> Result<usize, RtcpWriteError> {
        let entries = self.entries().count();
        if entries > u16::MAX as usize - 2 {
            return Err(RtcpWriteError::TooManyNack);
        }
        Ok(entries * 4)
    }

    fn write_into_unchecked(&self, buf: &mut [u8]) -> usize {
        let mut idx = 0;
        let mut end = idx;

        for entry in self.entries() {
            end += 4;
            buf[idx..end].copy_from_slice(&entry);
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
    use crate::feedback::TransportFeedback;

    fn nack_build_parse_n_consecutive_timestamps(start: u16, n: u16, fci: &[u8]) {
        nack_build_parse_n_m_timestamps(start, n, 1, fci)
    }

    fn nack_build_parse_n_m_timestamps(start: u16, n: u16, m: u16, fci: &[u8]) {
        assert!(n > 1);
        let r = (n + 1) % m;
        let req_len = TransportFeedback::MIN_PACKET_LEN + ((n - r + 16) / 17 * 4) as usize;
        let mut data = vec![0; req_len];
        let mut expected = vec![0; req_len];
        const TEMPLATE: [u8; 12] = [
            0x81, 0xcd, 0x00, 0x00, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba,
        ];
        expected[0..12].copy_from_slice(&TEMPLATE);
        expected[3] = (req_len / 4 - 1) as u8;
        expected[12..12 + fci.len()].copy_from_slice(fci);
        let nack = {
            let mut fci = Nack::builder();
            for i in (0..=n - 1).step_by(m as usize) {
                fci = fci.add_rtp_sequence(start + i);
            }
            TransportFeedback::builder_owned(fci)
                .sender_ssrc(0x98765432)
                .media_ssrc(0x10fedcba)
        };
        assert_eq!(nack.calculate_size().unwrap(), req_len);
        let len = nack.write_into(&mut data).unwrap();
        assert_eq!(len, req_len);
        assert_eq!(data, expected);

        let fb = TransportFeedback::parse(&data).unwrap();
        assert_eq!(fb.sender_ssrc(), 0x98765432);
        assert_eq!(fb.media_ssrc(), 0x10fedcba);
        let nack = fb.parse_fci::<Nack>().unwrap();
        let mut nack_iter = nack.entries();
        for i in (0..=n - 1).step_by(m as usize) {
            assert_eq!(nack_iter.next(), Some(0x1234 + i));
        }
        assert_eq!(nack_iter.next(), None);
    }

    #[test]
    fn nack_build_parse_2_consecutive_timestamps() {
        nack_build_parse_n_consecutive_timestamps(0x1234, 2, &[0x12, 0x34, 0x00, 0x01]);
    }

    #[test]
    fn nack_build_parse_16_consecutive_timestamps() {
        nack_build_parse_n_consecutive_timestamps(0x1234, 16, &[0x12, 0x34, 0x7f, 0xff]);
    }

    #[test]
    fn nack_build_parse_17_consecutive_timestamps() {
        nack_build_parse_n_consecutive_timestamps(0x1234, 17, &[0x12, 0x34, 0xff, 0xff]);
    }

    #[test]
    fn nack_build_parse_18_consecutive_timestamps() {
        nack_build_parse_n_consecutive_timestamps(
            0x1234,
            18,
            &[0x12, 0x34, 0xff, 0xff, 0x12, 0x45, 0x00, 0x00],
        );
    }

    #[test]
    fn nack_build_parse_12_2_timestamps() {
        nack_build_parse_n_m_timestamps(0x1234, 12, 2, &[0x12, 0x34, 0x02, 0b1010_1010]);
    }

    #[test]
    fn nack_build_ref_2_consecutive_timestamps() {
        let n = 2;
        let m = 1;
        let fci = &[0x12, 0x34, 0x00, 0x01];

        let r = (n + 1) % m;
        let req_len = TransportFeedback::MIN_PACKET_LEN + ((n - r + 16) / 17 * 4) as usize;
        let mut data = vec![0; req_len];
        let mut expected = vec![0; req_len];
        const TEMPLATE: [u8; 12] = [
            0x81, 0xcd, 0x00, 0x00, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba,
        ];
        expected[0..12].copy_from_slice(&TEMPLATE);
        expected[3] = (req_len / 4 - 1) as u8;
        expected[12..12 + fci.len()].copy_from_slice(fci);
        let mut fci = Nack::builder();
        for i in (0..=n - 1).step_by(m as usize) {
            fci = fci.add_rtp_sequence(0x1234 + i);
        }
        let nack = TransportFeedback::builder(&fci)
            .sender_ssrc(0x98765432)
            .media_ssrc(0x10fedcba);
        assert_eq!(nack.calculate_size().unwrap(), req_len);
        let len = nack.write_into(&mut data).unwrap();
        assert_eq!(len, req_len);
        assert_eq!(data, expected);
    }
}
