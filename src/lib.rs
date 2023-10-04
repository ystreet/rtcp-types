// SPDX-License-Identifier: MIT OR Apache-2.0

/// Errors that can be produced when parsing a RTCP packet
#[derive(Debug, PartialEq, Eq)]
pub enum RtcpParseError {
    /// Unsupported version.  This implementation only deals with version 2.
    UnsupportedVersion(u8),
    /// The packet was too short to parse
    Truncated {
        /// The expected size
        expected: usize,
        /// The actual size encountered
        actual: usize,
    },
    /// The packet was too large to parse
    TooLarge {
        /// The expected size
        expected: usize,
        /// The actual size encountered
        actual: usize,
    },
    /// This implementation does not handle this packet
    WrongImplementation,
}

mod app;
mod bye;
mod compound;
mod receiver;
mod sdes;
mod sender;
mod utils;

pub use app::App;
pub use bye::Bye;
pub use compound::{Compound, Packet, Unknown};
pub use receiver::ReceiverReport;
pub use sdes::{Sdes, SdesItem, SdesItemIter};
pub use sender::{ReportBlock, SenderReport};
