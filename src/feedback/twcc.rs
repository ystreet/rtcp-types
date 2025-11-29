// SPDX-License-Identifier: MIT OR Apache-2.0

use std::cmp;

use crate::feedback::FciFeedbackPacketType;
use crate::prelude::*;
use crate::utils::{pad_to_4bytes, u16_from_be_bytes};
use crate::{RtcpParseError, RtcpWriteError};

/// Maximum representable TWCC reference time.
///
/// The reference time is encoded in 24 bits as multiples of 64 ms.
pub const TWCC_MAX_REFERENCE_TIME: u32 = (1 << 24) - 1;

/// Transport-Wide Congestion Control FCI block
#[derive(Debug)]
pub struct Twcc<'a> {
    data: &'a [u8],
}

impl<'a> Twcc<'a> {
    /// See [`TwccBuilder::new`]
    pub fn builder(
        base_seq: u16,
        reference_time: u32,
        feedback_packet_count: u8,
        status_list: &[TwccPacketStatus],
        max_size: Option<usize>,
    ) -> TwccBuilder {
        TwccBuilder::new(
            base_seq,
            reference_time,
            feedback_packet_count,
            status_list,
            max_size,
        )
    }

    /// The transport-wide sequence number of the first packet in this feedback.
    ///
    /// This number is not necessarily increased for every feedback; in the case of reordering it may be decreased
    pub fn base_sequence_number(&self) -> u16 {
        u16_from_be_bytes(&self.data[0..2])
    }

    /// Signed integer indicating an absolute reference time in some (unknown) time base chosen by the sender of the
    /// feedback packets.
    ///
    /// The value is to be interpreted in multiples of 64ms.
    ///
    /// The first recv delta in this packet is relative to the reference time.
    ///
    /// The reference time makes it possible to calculate the delta between feedbacks even if some feedback packets are
    /// lost, since it always uses the same time base.
    pub fn reference_time(&self) -> u32 {
        u32::from_be_bytes([0, self.data[4], self.data[5], self.data[6]])
    }

    /// A counter incremented by one for each feedback packet sent. Used to detect feedback packet losses.
    pub fn feedback_packet_count(&self) -> u8 {
        self.data[7]
    }

    fn packet_status_count(&self) -> u16 {
        u16_from_be_bytes(&self.data[2..4])
    }

    fn packet_chunks(&self) -> impl Iterator<Item = PacketStatusChunk> + 'a {
        let mut remaining_status_count = self.packet_status_count();

        self.data[8..].chunks_exact(2).map_while(move |chunk| {
            if remaining_status_count == 0 {
                return None;
            }

            let chunk = u16_from_be_bytes(chunk);

            let chunk = if chunk & (1 << 15) == 0 {
                PacketStatusChunk::RunLength(StatusBits::from_two_bits(chunk >> 13), chunk & 0x1FFF)
            } else if chunk & (1 << 14) == 0 {
                PacketStatusChunk::Vector1Bit(chunk & 0x3FFF)
            } else {
                PacketStatusChunk::Vector2Bit(chunk & 0x3FFF)
            };

            remaining_status_count = remaining_status_count.saturating_sub(chunk.max_len());

            Some(chunk)
        })
    }

    /// Returns an iterator over all packets described by this TWCC feedback.
    ///
    /// The iterator yields `(sequence_number, status)` pairs in ascending sequence number order, starting from
    ///  [`Twcc::base_sequence_number`].
    pub fn packets(
        &self,
    ) -> impl Iterator<Item = Result<(u16, TwccPacketStatus), RtcpParseError>> + 'a {
        let mut remaining_packet_status_count = self.packet_status_count();
        let states = self.packet_chunks().flat_map(move |chunk| {
            let packet_status_iter = chunk
                .packet_status_iter()
                .take(remaining_packet_status_count.into());

            remaining_packet_status_count =
                remaining_packet_status_count.saturating_sub(chunk.max_len());

            packet_status_iter
        });

        let packet_chunks_count = self.packet_chunks().count();
        let mut deltas = self.data[8 + packet_chunks_count * 2..].iter();

        let mut sequence_number = self.base_sequence_number();

        states.map(move |status_bits| -> Result<_, RtcpParseError> {
            let packet_sequence_number = sequence_number;
            sequence_number = sequence_number.wrapping_add(1);

            let packet_status = match status_bits {
                StatusBits::NotReceived => TwccPacketStatus::NotReceived,
                StatusBits::ReceivedSmallDelta => {
                    // Single byte delta (0..63.75ms)
                    let delta_byte = *deltas.next().ok_or(RtcpParseError::TwccDeltaTruncated)?;

                    TwccPacketStatus::Received {
                        delta: i16::from(delta_byte),
                    }
                }
                StatusBits::ReceivedLargeOrNegativeDelta => {
                    // Two byte delta (-8192.0..8191.75 ms)
                    let delta_byte0 = *deltas.next().ok_or(RtcpParseError::TwccDeltaTruncated)?;
                    let delta_byte1 = *deltas.next().ok_or(RtcpParseError::TwccDeltaTruncated)?;

                    TwccPacketStatus::Received {
                        delta: i16::from_be_bytes([delta_byte0, delta_byte1]),
                    }
                }
                StatusBits::Reserved => return Err(RtcpParseError::TwccReservedPacketStatus),
            };

            Ok((packet_sequence_number, packet_status))
        })
    }
}

impl<'a> FciParser<'a> for Twcc<'a> {
    const PACKET_TYPE: FciFeedbackPacketType = FciFeedbackPacketType::TRANSPORT;
    const FCI_FORMAT: u8 = 15;

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

/// Status of a single packet in a TWCC feedback packet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwccPacketStatus {
    /// Packet was not received.
    NotReceived,

    /// Packet was received, with the given reception time delta in microseconds.
    Received {
        /// Delta is measured relative to the TWCC reference time, with a resolution of 250 µs.
        ///
        /// This value represents that delta as multiple of 250 µs.
        delta: i16,
    },
}

impl TwccPacketStatus {
    fn to_bits(self) -> StatusBits {
        match self {
            TwccPacketStatus::NotReceived => StatusBits::NotReceived,
            TwccPacketStatus::Received { delta } => {
                if (0..=255).contains(&delta) {
                    StatusBits::ReceivedSmallDelta
                } else {
                    StatusBits::ReceivedLargeOrNegativeDelta
                }
            }
        }
    }
}

/// Builder for a TWCC (Transport-Wide Congestion Control) FCI packet
#[derive(Debug)]
pub struct TwccBuilder {
    base_seq: u16,
    reference_time: u32,
    feedback_packet_count: u8,
    packet_status_count: u16,
    chunks: Vec<PacketStatusChunk>,
    deltas: Vec<u8>,
}

impl TwccBuilder {
    /// Create a new `TwccBuilder` with the given packet status list.
    ///
    /// `max_size` limits the number of bytes the FCI portion of the RTCP packet can use.
    /// If set, [`TwccBuilder::packet_status_count`] must be used to check how many status entries have been consumed.
    /// Any remaining status entries must be encoded in a separate feedback packet.
    pub fn new(
        base_seq: u16,
        reference_time: u32,
        feedback_packet_count: u8,
        status_list: &[TwccPacketStatus],
        max_size: Option<usize>,
    ) -> TwccBuilder {
        let mut this = TwccBuilder {
            base_seq,
            reference_time,
            feedback_packet_count,
            packet_status_count: 0,
            chunks: Vec::new(),
            deltas: Vec::new(),
        };

        this.set_status_list(status_list, max_size);

        this
    }

    fn set_status_list(&mut self, mut status_list: &[TwccPacketStatus], max_size: Option<usize>) {
        while let Some((mut chunk, mut consumed)) =
            PacketStatusChunk::from_packet_status_list(status_list)
        {
            // Check if the added chunk exceeds the provided max_size
            if let Some(max_size) = max_size {
                let projected_size = self.calculate_projected_size(status_list, consumed);

                if projected_size > max_size {
                    // Generated chunk is too large, if the chunk is a run length, it can be shortened to fit.
                    //
                    // Avoids returning 0 consumed packets if status only contains more Received packet status entries
                    // than `max_size` can fit.
                    if let PacketStatusChunk::RunLength(
                        status_bits @ (StatusBits::ReceivedSmallDelta
                        | StatusBits::ReceivedLargeOrNegativeDelta),
                        run_length,
                    ) = &mut chunk
                    {
                        let bytes_per_delta = match status_bits {
                            StatusBits::ReceivedSmallDelta => 1,
                            StatusBits::ReceivedLargeOrNegativeDelta => 2,
                            _ => unreachable!(),
                        };

                        let overshoot = pad_to_4bytes(projected_size - max_size);
                        if overshoot / bytes_per_delta > usize::from(*run_length - 1) {
                            return;
                        }

                        *run_length -= (overshoot / bytes_per_delta) as u16;
                        consumed -= overshoot / bytes_per_delta;
                    } else {
                        return;
                    }
                }
            }

            // Abort if there's more packet status entries than can fit into packet_status_count
            let packet_status_count = match self.packet_status_count.checked_add(consumed as u16) {
                Some(packet_status_count) => packet_status_count,
                _ => {
                    return;
                }
            };

            self.packet_status_count = packet_status_count;
            self.chunks.push(chunk);

            // Add deltas from consumed packet status entries
            for packet_status in &status_list[..consumed] {
                match *packet_status {
                    TwccPacketStatus::NotReceived => {
                        // No delta to add
                    }
                    TwccPacketStatus::Received { delta } => {
                        if let Ok(delta) = u8::try_from(delta) {
                            self.deltas.push(delta);
                        } else {
                            self.deltas.extend(delta.to_be_bytes());
                        }
                    }
                }
            }

            status_list = &status_list[consumed..];
        }
    }

    fn calculate_projected_size(
        &mut self,
        status_list: &[TwccPacketStatus],
        consumed: usize,
    ) -> usize {
        let additional_deltas_size: usize = status_list
            .iter()
            .take(consumed)
            .map(|packet_status| match packet_status.to_bits() {
                StatusBits::ReceivedSmallDelta => 1,
                StatusBits::ReceivedLargeOrNegativeDelta => 2,
                _ => 0,
            })
            .sum();

        let additional_size = additional_deltas_size + 2;
        let current_size = self.chunks.len() * 2 + self.deltas.len();

        pad_to_4bytes(8 + current_size + additional_size)
    }

    /// Number of packet status entries contained in this builder.
    pub fn packet_status_count(&self) -> usize {
        usize::from(self.packet_status_count)
    }
}

impl FciBuilder<'_> for TwccBuilder {
    fn format(&self) -> u8 {
        Twcc::FCI_FORMAT
    }

    fn supports_feedback_type(&self) -> FciFeedbackPacketType {
        Twcc::PACKET_TYPE
    }
}

impl RtcpPacketWriter for TwccBuilder {
    fn calculate_size(&self) -> Result<usize, RtcpWriteError> {
        if self.reference_time > TWCC_MAX_REFERENCE_TIME {
            return Err(RtcpWriteError::TwccReferenceTimeTooLarge);
        }

        let packet_chunks = self.chunks.len() * 2;
        let deltas = self.deltas.len();

        Ok(pad_to_4bytes(8 + packet_chunks + deltas))
    }

    fn write_into_unchecked(&self, buf: &mut [u8]) -> usize {
        buf[0..2].copy_from_slice(&self.base_seq.to_be_bytes());
        buf[2..4].copy_from_slice(&self.packet_status_count.to_be_bytes());
        buf[4..7].copy_from_slice(&self.reference_time.to_be_bytes()[1..]);
        buf[7] = self.feedback_packet_count;

        let mut idx = 8;

        for chunk in &self.chunks {
            buf[idx..(idx + 2)].copy_from_slice(&chunk.to_u16().to_be_bytes());
            idx += 2;
        }

        buf[idx..idx + self.deltas.len()].copy_from_slice(&self.deltas);

        pad_to_4bytes(idx + self.deltas.len())
    }

    fn get_padding(&self) -> Option<u8> {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacketStatusChunk {
    /// Indicates a packet status for n packets (13 bit length)
    RunLength(StatusBits, u16),

    /// Status vector with 1 bits per packet status (14 bits, 14 packets)
    Vector1Bit(u16),

    /// Status vector with 2 bits per packet status (14 bits, 7 packets)
    Vector2Bit(u16),
}

impl PacketStatusChunk {
    /// Consume items from a list of TwccPacketStatus into a single PacketStatusChunk
    ///
    /// Returns the chunk and the number of consumed TwccPacketStatus
    fn from_packet_status_list(
        status_list: &[TwccPacketStatus],
    ) -> Option<(PacketStatusChunk, usize)> {
        const RUN_LENGTH_MINIMUM: usize = 7;
        const CUTOFF_1BIT: usize = 14;
        const CUTOFF_2BIT: usize = 7;

        let first_status_bits = status_list.first()?.to_bits();
        let run_length = status_list
            .iter()
            .take_while(|packet_status| packet_status.to_bits() == first_status_bits)
            .take(0x1FFF)
            .count();

        let num_one_bit_status = status_list
            .iter()
            .take_while(|packet_status| packet_status.to_bits().is_one_bit())
            .take(14)
            .count();

        if run_length > RUN_LENGTH_MINIMUM && run_length >= num_one_bit_status {
            // Encode run length

            Some((
                PacketStatusChunk::RunLength(first_status_bits, run_length as u16),
                run_length,
            ))
        } else if (status_list.len() == num_one_bit_status && num_one_bit_status > CUTOFF_2BIT)
            || num_one_bit_status == CUTOFF_1BIT
        {
            // Encode one bit vector

            let num_one_bit_status = cmp::min(num_one_bit_status, CUTOFF_1BIT);

            let mut bits = 0u16;

            for (i, status) in status_list.iter().take(num_one_bit_status).enumerate() {
                debug_assert!(status.to_bits().is_one_bit());
                bits |= (status.to_bits() as u16) << (CUTOFF_1BIT - (i + 1));
            }

            Some((PacketStatusChunk::Vector1Bit(bits), num_one_bit_status))
        } else {
            // Encode two bit vector

            let mut bits = 0u16;

            for (i, status) in status_list.iter().take(CUTOFF_2BIT).enumerate() {
                bits |= (status.to_bits() as u16) << ((CUTOFF_2BIT - (i + 1)) * 2);
            }

            Some((
                PacketStatusChunk::Vector2Bit(bits),
                status_list.len().min(CUTOFF_2BIT),
            ))
        }
    }

    /// Maximum number of packet statuses this chunk represents
    fn max_len(&self) -> u16 {
        match self {
            PacketStatusChunk::RunLength(.., len) => *len,
            PacketStatusChunk::Vector1Bit(_) => 14,
            PacketStatusChunk::Vector2Bit(_) => 7,
        }
    }

    fn packet_status_iter(mut self) -> impl Iterator<Item = StatusBits> {
        (0..self.max_len()).map_while(move |offset| {
            let status = match &mut self {
                PacketStatusChunk::RunLength(status, len) => {
                    *len -= 1;
                    *status
                }
                PacketStatusChunk::Vector1Bit(bits) => {
                    StatusBits::from_one_bit(*bits >> (13 - offset))
                }
                PacketStatusChunk::Vector2Bit(bits) => {
                    StatusBits::from_two_bits(*bits >> (12 - (offset * 2)))
                }
            };

            Some(status)
        })
    }

    fn to_u16(self) -> u16 {
        match self {
            PacketStatusChunk::RunLength(status, run_length) => {
                //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                // |T| S |       Run Length        |
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                // T = 0 for Run Length Chunk
                // S = status
                ((status as u16) << 13) | (run_length & 0x1F_FF)
            }
            PacketStatusChunk::Vector1Bit(bits) => {
                //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                // |T|S|       symbol list         |
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                // T = 1 for Status Vector Chunk
                // S = 0 so this vector only contains 1 bit per status (Received = 0 and NotReceived = 1)
                0x8000 | (bits & 0x3F_FF)
            }
            PacketStatusChunk::Vector2Bit(bits) => {
                //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                // |T|S|       symbol list         |
                // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                // T = 1 for Status Vector Chunk
                // S = 1 so this vector contains 2 bits per status (See TwccPacketStatus)
                0xC000 | (bits & 0x3F_FF)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
enum StatusBits {
    NotReceived = 0,
    ReceivedSmallDelta = 1,
    ReceivedLargeOrNegativeDelta = 2,
    Reserved = 3,
}

impl StatusBits {
    fn from_two_bits(bits: u16) -> StatusBits {
        match bits & 0b11 {
            0 => StatusBits::NotReceived,
            1 => StatusBits::ReceivedSmallDelta,
            2 => StatusBits::ReceivedLargeOrNegativeDelta,
            3 => StatusBits::Reserved,
            _ => unreachable!(),
        }
    }

    fn from_one_bit(bit: u16) -> StatusBits {
        match bit & 0b1 {
            0 => StatusBits::NotReceived,
            1 => StatusBits::ReceivedSmallDelta,
            _ => unreachable!(),
        }
    }

    fn is_one_bit(&self) -> bool {
        matches!(
            self,
            StatusBits::NotReceived | StatusBits::ReceivedSmallDelta
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{random, Rng};

    #[test]
    fn parse_packet_chunk() {
        use PacketStatusChunk as C;
        use StatusBits as B;

        assert!(C::RunLength(B::NotReceived, 64)
            .packet_status_iter()
            .all(|c| c == StatusBits::NotReceived));
        assert_eq!(
            C::RunLength(B::NotReceived, 64)
                .packet_status_iter()
                .count(),
            64
        );

        assert_eq!(
            C::Vector1Bit(0b00_10_01_01_10_00_00_00)
                .packet_status_iter()
                .collect::<Vec<_>>(),
            [
                B::ReceivedSmallDelta,
                B::NotReceived,
                B::NotReceived,
                B::ReceivedSmallDelta,
                B::NotReceived,
                B::ReceivedSmallDelta,
                B::ReceivedSmallDelta,
                B::NotReceived,
                B::NotReceived,
                B::NotReceived,
                B::NotReceived,
                B::NotReceived,
                B::NotReceived,
                B::NotReceived,
            ],
        );

        assert_eq!(
            C::Vector2Bit(0b00_10_01_01_10_00_11_00)
                .packet_status_iter()
                .take(6)
                .collect::<Vec<_>>(),
            [
                B::ReceivedLargeOrNegativeDelta,
                B::ReceivedSmallDelta,
                B::ReceivedSmallDelta,
                B::ReceivedLargeOrNegativeDelta,
                B::NotReceived,
                B::Reserved,
            ],
        );
    }

    #[test]
    fn serialize_packet_chunk() {
        use PacketStatusChunk as C;
        use StatusBits as B;

        assert_eq!(
            C::RunLength(B::ReceivedSmallDelta, 64).to_u16(),
            0b0010_0000_0100_0000
        );
        assert_eq!(
            C::RunLength(B::NotReceived, 256).to_u16(),
            0b0000_0001_0000_0000
        );
        assert_eq!(
            C::RunLength(B::ReceivedLargeOrNegativeDelta, 1024).to_u16(),
            0b0100_0100_0000_0000
        );

        assert_eq!(
            C::Vector1Bit(0b0011_0011_0011_0011).to_u16(),
            0b1011_0011_0011_0011
        );

        assert_eq!(
            C::Vector1Bit(0b0000_1100_1100_1100).to_u16(),
            0b1000_1100_1100_1100
        );

        assert_eq!(
            C::Vector2Bit(0b0011_0011_0011_0011).to_u16(),
            0b1111_0011_0011_0011
        );
        assert_eq!(
            C::Vector2Bit(0b0000_1100_1100_1100).to_u16(),
            0b1100_1100_1100_1100
        );
    }

    #[test]
    fn packet_chunk_from_status() {
        let (chunk, consumed) =
            PacketStatusChunk::from_packet_status_list(&[TwccPacketStatus::NotReceived]).unwrap();
        assert_eq!(consumed, 1);
        assert_eq!(chunk, PacketStatusChunk::Vector2Bit(0));

        let (chunk, consumed) = PacketStatusChunk::from_packet_status_list(&[
            TwccPacketStatus::Received { delta: 0 },
            TwccPacketStatus::NotReceived,
            TwccPacketStatus::Received { delta: -1 },
        ])
        .unwrap();
        assert_eq!(consumed, 3);
        assert_eq!(
            chunk,
            PacketStatusChunk::Vector2Bit(0b00_01_00_10_00_00_00_00)
        );

        // 2 Bit even when list is longer due to negative delta
        let (chunk, consumed) = PacketStatusChunk::from_packet_status_list(&[
            TwccPacketStatus::Received { delta: 0 },
            TwccPacketStatus::NotReceived,
            TwccPacketStatus::Received { delta: -1 },
            TwccPacketStatus::NotReceived,
            TwccPacketStatus::NotReceived,
            TwccPacketStatus::NotReceived,
            TwccPacketStatus::Received { delta: 1 },
            TwccPacketStatus::NotReceived,
            TwccPacketStatus::NotReceived,
        ])
        .unwrap();
        assert_eq!(consumed, 7);
        assert_eq!(
            chunk,
            PacketStatusChunk::Vector2Bit(0b00_01_00_10_00_00_00_01)
        );

        // 1 Bit when list is longer than 7
        let (chunk, consumed) = PacketStatusChunk::from_packet_status_list(&[
            TwccPacketStatus::Received { delta: 0 },
            TwccPacketStatus::NotReceived,
            TwccPacketStatus::Received { delta: 1 },
            TwccPacketStatus::NotReceived,
            TwccPacketStatus::NotReceived,
            TwccPacketStatus::NotReceived,
            TwccPacketStatus::Received { delta: 0 },
            TwccPacketStatus::NotReceived,
            TwccPacketStatus::NotReceived,
        ])
        .unwrap();
        assert_eq!(consumed, 9);
        assert_eq!(
            chunk,
            PacketStatusChunk::Vector1Bit(0b00_10_10_00_10_00_00_00)
        );

        // Run length when viable
        let mut status = vec![TwccPacketStatus::NotReceived; 26];
        status.push(TwccPacketStatus::Received { delta: -1 });

        let (chunk, consumed) = PacketStatusChunk::from_packet_status_list(&status).unwrap();
        assert_eq!(consumed, 26);
        assert_eq!(
            chunk,
            PacketStatusChunk::RunLength(StatusBits::NotReceived, 26)
        );
    }

    fn build_and_parse_all(mut status_list: &[TwccPacketStatus], max_size: Option<usize>) {
        let mut base_seq = rand::random::<u16>();

        while !status_list.is_empty() {
            let fci = Twcc::builder(base_seq, 0, rand::random(), status_list, max_size);

            let consumed = fci.packet_status_count();
            assert_ne!(consumed, 0);

            let size = fci.calculate_size().unwrap();
            if let Some(max_size) = max_size {
                assert!(size <= max_size, "max_size: {max_size}, size: {size}");
            }

            let mut buf = vec![0u8; size];
            fci.write_into(&mut buf).unwrap();

            let twcc = Twcc::parse(&buf).unwrap();
            assert_eq!(
                twcc.packets()
                    .enumerate()
                    .map(|(i, result)| {
                        let (seq, p) = result.unwrap();
                        let expected_seq = base_seq.wrapping_add(i.try_into().unwrap());
                        assert_eq!(seq, expected_seq);
                        p
                    })
                    .collect::<Vec<_>>(),
                status_list[..consumed],
            );

            base_seq = base_seq.wrapping_add(consumed.try_into().unwrap());
            status_list = &status_list[consumed..];
        }
    }

    #[test]
    fn random_permutations() {
        let mut status_list = Vec::new();

        for _ in 0..100 {
            status_list.clear();

            let len = rand::thread_rng().gen_range(200..1000);

            for _ in 0..len {
                if rand::thread_rng().gen_bool(0.05) {
                    status_list.extend(std::iter::repeat_n(
                        TwccPacketStatus::NotReceived,
                        rand::thread_rng().gen_range(1..3000),
                    ));
                } else if rand::thread_rng().gen_bool(0.8) {
                    status_list.push(TwccPacketStatus::Received {
                        delta: rand::thread_rng().gen_range(0..20),
                    });
                } else {
                    status_list.push(TwccPacketStatus::Received { delta: random() });
                }
            }

            build_and_parse_all(&status_list, Some(rand::thread_rng().gen_range(800..1500)));
        }
    }

    #[test]
    fn too_many_deltas_for_max_size() {
        const MAX_SIZE_FOR_1000_STATUS: usize = 1012;

        let status_list = vec![TwccPacketStatus::Received { delta: 0 }; 2000];

        let builder = TwccBuilder::new(0, 0, 0, &status_list, Some(MAX_SIZE_FOR_1000_STATUS));

        assert_eq!(builder.packet_status_count(), 1000);

        let builder = TwccBuilder::new(
            0,
            0,
            0,
            &status_list[builder.packet_status_count()..],
            Some(MAX_SIZE_FOR_1000_STATUS),
        );

        assert_eq!(builder.packet_status_count(), 1000);
    }

    #[test]
    fn missing_deltas() {
        let status_list = vec![TwccPacketStatus::Received { delta: 123 }; 5];
        let builder = TwccBuilder::new(100, 0, 0, &status_list, None);

        let mut buffer = vec![0u8; builder.calculate_size().unwrap()];
        builder.write_into(&mut buffer).unwrap();

        // Truncate deltas from then end
        buffer.truncate(buffer.len() - 3);

        let parsed = Twcc::parse(&buffer).unwrap();
        let packets = parsed.packets().collect::<Vec<_>>();

        assert!(matches!(
            packets[0],
            Ok((100, TwccPacketStatus::Received { delta: 123 }))
        ));
        assert!(matches!(
            packets[1],
            Ok((101, TwccPacketStatus::Received { delta: 123 }))
        ));
        assert!(matches!(
            packets[2],
            Ok((102, TwccPacketStatus::Received { delta: 123 }))
        ));
        assert!(matches!(
            packets[3],
            Err(RtcpParseError::TwccDeltaTruncated)
        ));
        assert!(matches!(
            packets[4],
            Err(RtcpParseError::TwccDeltaTruncated)
        ));
    }
}
