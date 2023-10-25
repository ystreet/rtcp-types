// SPDX-License-Identifier: MIT OR Apache-2.0

/// A Trait defining RTCP Packet structural data.
pub trait RtcpPacket {
    const VERSION: u8 = 2;
    const MAX_COUNT: u8 = 0x1f;
    const MIN_PACKET_LEN: usize;
    const PACKET_TYPE: u8;
}

/// Errors that can be produced when parsing a RTCP packet
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum RtcpParseError {
    /// Unsupported version.  This implementation only deals with version 2.
    #[error("Unsupported version: {}.  This implementation only deals with version 2.", .0)]
    UnsupportedVersion(u8),
    /// The packet was too short to parse
    #[error("The packet was too short to parse. Expected size: {expected}, actual size encountered: {actual}")]
    Truncated {
        /// The expected size
        expected: usize,
        /// The actual size encountered
        actual: usize,
    },
    /// The packet was too large to parse
    #[error("The packet was too large to parse. Expected size: {expected}, actual size encountered: {actual}")]
    TooLarge {
        /// The expected size
        expected: usize,
        /// The actual size encountered
        actual: usize,
    },
    /// Invalid Padding length 0.
    #[error("Invalid Padding length 0")]
    InvalidPadding,

    /// The SDES Value was too large
    #[error("The SDES Value length {len} was too large (max {max})")]
    SdesValueTooLarge {
        /// The length
        len: usize,
        /// The maximum length allowed
        max: u8,
    },

    /// The SDES PRIV content was too short
    #[error("The SDES PRIC content length {len} was too short (min {min})")]
    SdesPrivContentTruncated {
        /// The length
        len: usize,
        /// The minimum length allowed
        min: u8,
    },

    /// The SDES PRIV prefix was too large
    #[error("The SDES PRIV prefix length {len} too large (available {available})")]
    SdesPrivPrefixTooLarge {
        /// The length
        len: usize,
        /// The maximum length available
        available: u8,
    },

    /// This implementation does not handle this packet
    #[error("This implementation does not handle this packet")]
    WrongImplementation,
}

/// Errors produced when writing a packet
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum RtcpWriteError {
    /// Output buffer is not large enough to fit the resulting buffer.  The requested size is
    /// returned.
    #[error("Output buffer is not large enough to fit the resulting buffer. Requested size: {}", .0)]
    OutputTooSmall(usize),

    /// The provided padding is not a multiple of 4.
    #[error("The provided padding {padding} is not a multiple of 4")]
    InvalidPadding { padding: u8 },

    /// App Subtype was out of range.
    #[error("App Subtype {subtype} was out of range (max: {max})")]
    AppSubtypeOutOfRange { subtype: u8, max: u8 },

    /// APP Packet Name is invalid.  Expecting a sequence of four ASCII characters.
    #[error("APP Packet Name is invalid.  Expecting a sequence of four ASCII characters.")]
    InvalidName,

    /// Data length must be a mutliple of 32bits.  The data length is returned.
    #[error("Data length must be a mutliple of 32bits. Data len: {}", .0)]
    DataLen32bitMultiple(usize),

    /// Too many Sources specified.
    #[error("Too many Sources specified. Number of Sources: {count}, max: {max}")]
    TooManySources { count: usize, max: u8 },

    /// Reason length was too large.
    #[error("Reason length {len} was too large (max {max})")]
    ReasonLenTooLarge { len: usize, max: u8 },

    /// Cumulative Lost was too large.
    #[error("Cumulative Lost {value} was too large (max {max})")]
    CumulativeLostTooLarge { value: u32, max: u32 },

    /// Too many Report Blocks specified (max 31).
    #[error("Too many Report Blocks specified. Number of Report Blocks: {count} max: {max}")]
    TooManyReportBlocks { count: usize, max: u8 },

    /// Too many SDES Chunks specified.
    #[error("Too many SDES Chunks specified. Number of SDES Chunks: {count}, max: {max}")]
    TooManySdesChunks { count: usize, max: u8 },

    /// SDES Value length was too large.
    #[error("SDES Value length {len} was too large (max {max})")]
    SdesValueTooLarge { len: usize, max: u8 },

    /// The SDES PRIV prefix was too large.
    #[error("The SDES PRIV prefix length {len} too large (max {max})")]
    SdesPrivPrefixTooLarge { len: usize, max: u8 },

    /// Unknown Count was out of range.
    #[error("Unknown Count {count} was out of range (max: {max})")]
    CountOutOfRange { count: u8, max: u8 },

    /// Non-last Compound packet padding defined.
    #[error("Non-last Compound packet padding defined")]
    NonLastCompoundPacketPadding,
}

impl From<RtcpParseError> for RtcpWriteError {
    fn from(err: RtcpParseError) -> Self {
        match err {
            RtcpParseError::SdesValueTooLarge { len, max } => {
                RtcpWriteError::SdesValueTooLarge { len, max }
            }
            RtcpParseError::SdesPrivPrefixTooLarge { len, available } => {
                RtcpWriteError::SdesPrivPrefixTooLarge {
                    len,
                    max: available,
                }
            }
            other => unreachable!("{other}"),
        }
    }
}

mod app;
mod bye;
mod compound;
mod receiver;
mod report_block;
mod sdes;
mod sender;
mod utils;

pub use app::{App, AppBuilder};
pub use bye::{Bye, ByeBuilder};
pub use compound::{Compound, CompoundBuilder, Unknown, UnknownBuilder, Packet, PacketBuilder};
pub use receiver::{ReceiverReport, ReceiverReportBuilder};
pub use report_block::{ReportBlock, ReportBlockBuilder};
pub use sdes::{Sdes, SdesItem, SdesBuilder, SdesItemBuilder, SdesChunk, SdesChunkBuilder};
pub use sender::{SenderReport, SenderReportBuilder};
