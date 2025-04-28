// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::feedback::FciFeedbackPacketType;
use crate::{prelude::*, RtcpParseError, RtcpWriteError};

/// Slice Loss Information
#[derive(Debug)]
pub struct Sli<'a> {
    data: &'a [u8],
}

impl Sli<'_> {
    /// The macro blocks that have been lost
    pub fn lost_macroblocks(&self) -> impl Iterator<Item = MacroBlockEntry> + '_ {
        MacroBlockIter {
            data: self.data,
            i: 0,
        }
    }

    /// Create a new [`SliBuilder`]
    pub fn builder() -> SliBuilder {
        SliBuilder { lost_mbs: vec![] }
    }
}

impl<'a> FciParser<'a> for Sli<'a> {
    const PACKET_TYPE: FciFeedbackPacketType = FciFeedbackPacketType::PAYLOAD;
    const FCI_FORMAT: u8 = 2;

    fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        if data.len() < 4 {
            return Err(RtcpParseError::Truncated {
                expected: 4,
                actual: data.len(),
            });
        }
        Ok(Self { data })
    }
}

struct MacroBlockIter<'a> {
    data: &'a [u8],
    i: usize,
}

impl Iterator for MacroBlockIter<'_> {
    type Item = MacroBlockEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.i + 3 > self.data.len() {
            return None;
        }
        let data = [
            self.data[self.i],
            self.data[self.i + 1],
            self.data[self.i + 2],
            self.data[self.i + 3],
        ];
        self.i += 4;
        Some(MacroBlockEntry::decode(data))
    }
}

/// A macro block entry
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct MacroBlockEntry {
    start: u16,
    count: u16,
    picture_id: u8,
}

impl MacroBlockEntry {
    fn encode(&self) -> [u8; 4] {
        let mut ret = [0; 4];
        ret[0] = ((self.start & 0x1fe0) >> 5) as u8;
        ret[1] = ((self.start & 0x1f) << 3) as u8 | ((self.count & 0x1c00) >> 10) as u8;
        ret[2] = ((self.count & 0x03fc) >> 2) as u8;
        ret[3] = ((self.count & 0x0003) as u8) << 6 | self.picture_id & 0x3f;
        ret
    }

    fn decode(data: [u8; 4]) -> Self {
        let start = (data[0] as u16) << 5 | (data[1] as u16 & 0xf8) >> 3;
        let count =
            ((data[1] & 0x07) as u16) << 10 | (data[2] as u16) << 2 | (data[3] as u16 & 0xc0) >> 6;
        let picture_id = data[3] & 0x3f;
        Self {
            start,
            count,
            picture_id,
        }
    }
}

/// Builder for Slice Loss Information
#[derive(Debug)]
pub struct SliBuilder {
    lost_mbs: Vec<MacroBlockEntry>,
}

impl SliBuilder {
    /// Add a lost macro block to the SLI
    pub fn add_lost_macroblock(
        mut self,
        start_macroblock: u16,
        count_macroblocks: u16,
        picture_id: u8,
    ) -> Self {
        self.lost_mbs.push(MacroBlockEntry {
            start: start_macroblock,
            count: count_macroblocks,
            picture_id,
        });
        self
    }
}

impl FciBuilder<'_> for SliBuilder {
    fn format(&self) -> u8 {
        2
    }

    fn supports_feedback_type(&self) -> FciFeedbackPacketType {
        FciFeedbackPacketType::PAYLOAD
    }
}

impl RtcpPacketWriter for SliBuilder {
    fn calculate_size(&self) -> Result<usize, RtcpWriteError> {
        Ok(4 * self.lost_mbs.len())
    }

    fn write_into_unchecked(&self, buf: &mut [u8]) -> usize {
        let mut idx = 0;
        for entry in self.lost_mbs.iter() {
            let encoded = entry.encode();
            buf[idx] = encoded[0];
            buf[idx + 1] = encoded[1];
            buf[idx + 2] = encoded[2];
            buf[idx + 3] = encoded[3];
            idx += 4;
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
    fn macroblock_entries() {
        let mut start = 0;
        loop {
            let mut count = 0;
            loop {
                for picture_id in 0..=0x3f {
                    let mbe = MacroBlockEntry {
                        start,
                        count,
                        picture_id,
                    };
                    let other = MacroBlockEntry::decode(mbe.encode());
                    assert_eq!(mbe, other);
                }
                count = (count << 1) | 1;
                if count > 0x1fff {
                    break;
                }
            }
            start = (start << 1) | 1;
            if start > 0x1fff {
                break;
            }
        }
    }

    #[test]
    fn sli_build_parse() {
        const REQ_LEN: usize = PayloadFeedback::MIN_PACKET_LEN + 4;
        let mut data = [0; REQ_LEN];
        let sli = {
            let fci = Sli::builder().add_lost_macroblock(0x1234, 0x0987, 0x25);
            PayloadFeedback::builder_owned(fci)
                .sender_ssrc(0x98765432)
                .media_ssrc(0x10fedcba)
        };
        assert_eq!(sli.calculate_size().unwrap(), REQ_LEN);
        let len = sli.write_into(&mut data).unwrap();
        assert_eq!(len, REQ_LEN);
        assert_eq!(
            data,
            [
                0x82, 0xce, 0x00, 0x03, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x91, 0xa2,
                0x61, 0xe5
            ]
        );

        let fb = PayloadFeedback::parse(&data).unwrap();

        assert_eq!(fb.sender_ssrc(), 0x98765432);
        assert_eq!(fb.media_ssrc(), 0x10fedcba);
        let sli = fb.parse_fci::<Sli>().unwrap();
        let mut mb_iter = sli.lost_macroblocks();
        assert_eq!(
            mb_iter.next(),
            Some(MacroBlockEntry {
                start: 0x1234,
                count: 0x987,
                picture_id: 0x25
            })
        );
        assert_eq!(mb_iter.next(), None);
    }

    #[test]
    fn sli_build_ref() {
        const REQ_LEN: usize = PayloadFeedback::MIN_PACKET_LEN + 4;
        let mut data = [0; REQ_LEN];
        let fci = Sli::builder().add_lost_macroblock(0x1234, 0x0987, 0x25);
        let sli = PayloadFeedback::builder(&fci)
            .sender_ssrc(0x98765432)
            .media_ssrc(0x10fedcba);
        assert_eq!(sli.calculate_size().unwrap(), REQ_LEN);
        let len = sli.write_into(&mut data).unwrap();
        assert_eq!(len, REQ_LEN);
        assert_eq!(
            data,
            [
                0x82, 0xce, 0x00, 0x03, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x91, 0xa2,
                0x61, 0xe5
            ]
        );
    }
}
