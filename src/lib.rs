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
    /// This implementation does not handle this packet
    #[error("This implementation does not handle this packet")]
    WrongImplementation,
}

mod app;
mod bye;
mod compound;
mod receiver;
mod report_block;
mod sdes;
mod sender;
mod utils;

pub use app::App;
pub use bye::Bye;
pub use compound::{Compound, Packet, Unknown};
pub use receiver::ReceiverReport;
pub use report_block::ReportBlock;
pub use sdes::{Sdes, SdesItem, SdesItemIter};
pub use sender::SenderReport;
