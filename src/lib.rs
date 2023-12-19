// SPDX-License-Identifier: MIT OR Apache-2.0

/// A Trait defining RTCP Packet structural data.
pub trait RtcpPacket {
    const VERSION: u8 = 2;
    const MAX_COUNT: u8 = 0x1f;
    const MIN_PACKET_LEN: usize;
    const PACKET_TYPE: u8;
}

/// A Trait to ease the implementation of RTCP Packet parsers.
///
/// Implementers only need to return the 4 byte RTCP header
/// from [`RtcpPacketParser::header_data`] to be able to use
/// the getters for the common RTCP packet fields.
pub trait RtcpPacketParser<'a>: RtcpPacket + Sized {
    /// Parses the provided data.
    ///
    /// Returns an instance of `Self` if parsing succeeds,
    /// an `RtcpParseError` otherwise.
    fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError>;

    /// Returns the common header for this RTCP packet.
    fn header_data(&self) -> [u8; 4];
}

pub trait RtcpPacketParserExt<'a>: RtcpPacketParser<'a> {
    fn version(&self) -> u8 {
        utils::parser::parse_version(&self.header_data())
    }

    fn type_(&self) -> u8 {
        utils::parser::parse_packet_type(&self.header_data())
    }

    fn subtype(&self) -> u8 {
        utils::parser::parse_count(&self.header_data())
    }

    fn length(&self) -> usize {
        utils::parser::parse_length(&self.header_data())
    }

    fn count(&self) -> u8 {
        utils::parser::parse_count(&self.header_data())
    }
}

impl<'a, T: RtcpPacketParser<'a>> RtcpPacketParserExt<'a> for T {}

/// A Trait with base functions needed for RTCP Packet writers.
///
/// Note: this trait must remain [object-safe].
///
/// [object-safe]: https://doc.rust-lang.org/reference/items/traits.html#object-safety
pub trait RtcpPacketWriter: std::fmt::Debug {
    /// Calculates the size required to write this RTCP packet.
    ///
    /// Also performs validity checks.
    fn calculate_size(&self) -> Result<usize, RtcpWriteError>;

    /// Writes this RTCP packet into `buf` without any validity checks.
    ///
    /// Uses the length of the buffer for the length field.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Panic
    ///
    /// Panics if the buf is not large enough.
    fn write_into_unchecked(&self, buf: &mut [u8]) -> usize;

    /// Gets the padding that was configured for this RTCP packet.
    fn get_padding(&self) -> Option<u8>;
}

pub trait RtcpPacketWriterExt: RtcpPacketWriter {
    /// Writes the Custom packet into `buf`.
    ///
    /// The default implementation:
    ///
    /// * Calls [`RtcpPacketWriter::calculate_size`] for validity checks and size calculation.
    /// * Checks that the provided buffer is large enough to store this RTCP packet.
    /// * Writes to the provided buffer using [`RtcpPacketWriter::write_into_unchecked`].
    fn write_into(&self, buf: &mut [u8]) -> Result<usize, RtcpWriteError> {
        let req_size = self.calculate_size()?;
        if buf.len() < req_size {
            return Err(RtcpWriteError::OutputTooSmall(req_size));
        }

        Ok(self.write_into_unchecked(&mut buf[..req_size]))
    }
}

impl<T: RtcpPacketWriter> RtcpPacketWriterExt for T {}

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

    /// RTCP Packet type mismatch.
    #[error("RTCP Packet type mismatch. Actual: {actual}, requested {requested}")]
    PacketTypeMismatch { actual: u8, requested: u8 },
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

    /// Feedback packet does not have any FCI defined.
    #[error("Feedback packet does not contain any FCI data")]
    MissingFci,

    /// Number of NACK's will not fit within a single RTCP packet.
    #[error("The number of NACK entries will not fit inside a RTCP packet.")]
    TooManyNack,

    /// Feedback packet does not support this FCI data.
    #[error("Wrong feedback packet type for the provided FCI data")]
    FciWrongFeedbackPacketType,

    /// Payload type value out of range.
    #[error("The RTP payload value is not a valid value")]
    PayloadTypeInvalid,

    /// Payload type value out of range.
    #[error("The amount of padding bits are greater than the size of the data")]
    PaddingBitsTooLarge,

    /// Number of FIR's will not fit within a single RTCP packet.
    #[error("The number of FIR entries will not fit inside a RTCP packet.")]
    TooManyFir,
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
mod feedback;
mod receiver;
mod report_block;
mod sdes;
mod sender;
pub mod utils;

pub use app::{App, AppBuilder};
pub use bye::{Bye, ByeBuilder};
pub use compound::{Compound, CompoundBuilder, Packet, PacketBuilder, Unknown, UnknownBuilder};
pub use feedback::fir::{Fir, FirBuilder, FirEntry};
pub use feedback::nack::{Nack, NackBuilder};
pub use feedback::pli::{Pli, PliBuilder};
pub use feedback::rpsi::{Rpsi, RpsiBuilder};
pub use feedback::sli::{Sli, SliBuilder};
pub use feedback::{
    FciBuilder, FciParser, PayloadFeedback, PayloadFeedbackBuilder, TransportFeedback,
    TransportFeedbackBuilder,
};
pub use receiver::{ReceiverReport, ReceiverReportBuilder};
pub use report_block::{ReportBlock, ReportBlockBuilder};
pub use sdes::{Sdes, SdesBuilder, SdesChunk, SdesChunkBuilder, SdesItem, SdesItemBuilder};
pub use sender::{SenderReport, SenderReportBuilder};

pub mod prelude {
    pub use super::{
        FciBuilder, FciParser, RtcpPacket, RtcpPacketParser, RtcpPacketParserExt, RtcpPacketWriter,
        RtcpPacketWriterExt,
    };
}
