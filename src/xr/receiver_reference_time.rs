// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::prelude::*;
use crate::utils::u64_from_be_bytes;
use crate::xr::{XrBlockBuilder, XrBlockParser, XrBlockStaticType};
use crate::{RtcpParseError, RtcpWriteError};

/// Receiver Reference Time information as specified in RFC 3611
#[derive(Debug)]
pub struct ReceiverReferenceTime<'a> {
    data: &'a [u8],
}

impl XrBlockStaticType for ReceiverReferenceTime<'_> {
    const BLOCK_TYPE: u8 = 0x4;
}

impl<'a> XrBlockParser<'a> for ReceiverReferenceTime<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        if data.len() < 12 {
            return Err(RtcpParseError::Truncated {
                expected: 12,
                actual: data.len(),
            });
        }
        let ret = Self { data };
        Ok(ret)
    }

    #[inline(always)]
    fn header_data(&self) -> [u8; 4] {
        self.data[..4].try_into().unwrap()
    }
}

impl ReceiverReferenceTime<'_> {
    /// The 32.32 fixed point NTP timestamp sampled at the same time as the RTP timestamp
    pub fn ntp_timestamp(&self) -> u64 {
        u64_from_be_bytes(&self.data[4..12])
    }

    /// Returns a [`ReceiverReferenceTimeBuilder`] for constructing a [`ReceiverReferenceTime`] block.
    pub fn builder() -> ReceiverReferenceTimeBuilder {
        ReceiverReferenceTimeBuilder::default()
    }
}

/// A builder for a [`ReceiverReferenceTime`]
#[derive(Debug, Default)]
pub struct ReceiverReferenceTimeBuilder {
    ntp_timestamp: u64,
}

impl ReceiverReferenceTimeBuilder {
    /// Sets the NTP timestamp.
    pub fn ntp_timestamp(mut self, ntp_timestamp: u64) -> Self {
        self.ntp_timestamp = ntp_timestamp;
        self
    }
}

impl XrBlockBuilder<'_> for ReceiverReferenceTimeBuilder {
    fn type_specific_byte(&self) -> u8 {
        0
    }
}

impl RtcpPacketWriter for ReceiverReferenceTimeBuilder {
    fn calculate_size(&self) -> Result<usize, RtcpWriteError> {
        Ok(12)
    }

    fn write_into_unchecked(&self, buf: &mut [u8]) -> usize {
        self.write_header_unchecked(buf, ReceiverReferenceTime::BLOCK_TYPE, 2);
        buf[4..12].copy_from_slice(&self.ntp_timestamp.to_be_bytes());

        12
    }

    fn get_padding(&self) -> Option<u8> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receive_reference_time_builder() {
        let builder = ReceiverReferenceTime::builder().ntp_timestamp(0x1234_5678_90ab_cdef);
        let len = builder.calculate_size().unwrap();
        let mut buf = vec![0; len];
        builder.write_into(&mut buf).unwrap();

        let rrt = ReceiverReferenceTime::parse(&buf).unwrap();
        assert_eq!(rrt.ntp_timestamp(), 0x1234_5678_90ab_cdef);
    }
}
