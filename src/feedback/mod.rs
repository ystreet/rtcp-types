// SPDX-License-Identifier: MIT OR Apache-2.0

use std::borrow::Borrow;

use crate::{
    prelude::*,
    utils::{pad_to_4bytes, parser, writer},
    RtcpPacket, RtcpPacketParser, RtcpParseError, RtcpWriteError,
};

pub mod fir;
pub mod nack;
pub mod pli;
pub mod rpsi;
pub mod sli;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct FciFeedbackPacketType {
    transport: bool,
    payload: bool,
}

impl FciFeedbackPacketType {
    pub const NONE: Self = Self {
        transport: false,
        payload: false,
    };
    pub const TRANSPORT: Self = Self {
        transport: true,
        payload: false,
    };
    pub const PAYLOAD: Self = Self {
        transport: false,
        payload: true,
    };
}

impl std::ops::BitOr<FciFeedbackPacketType> for FciFeedbackPacketType {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self {
            transport: self.transport | rhs.transport,
            payload: self.payload | rhs.payload,
        }
    }
}

impl std::ops::BitAnd<FciFeedbackPacketType> for FciFeedbackPacketType {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        Self {
            transport: self.transport & rhs.transport,
            payload: self.payload & rhs.payload,
        }
    }
}

/// A parsed (Transport) Feedback packet as specified in RFC 4585.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportFeedback<'a> {
    data: &'a [u8],
}

impl<'a> RtcpPacket for TransportFeedback<'a> {
    const MIN_PACKET_LEN: usize = 12;
    const PACKET_TYPE: u8 = 205;
}

impl<'a> RtcpPacketParser<'a> for TransportFeedback<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        parser::check_packet::<Self>(data)?;
        Ok(Self { data })
    }

    #[inline(always)]
    fn header_data(&self) -> [u8; 4] {
        self.data[..4].try_into().unwrap()
    }
}

impl<'a> TransportFeedback<'a> {
    /// Constructs a [`TransportFeedbackBuilder`] which refers to the provided [`FciBuilder`].
    ///
    /// Use [`TransportFeedback::builder_owned`] to return the [`TransportFeedbackBuilder`]
    /// from a function.
    pub fn builder(fci: &'a dyn FciBuilder<'a>) -> TransportFeedbackBuilder<'a> {
        TransportFeedbackBuilder {
            padding: 0,
            sender_ssrc: 0,
            media_ssrc: 0,
            fci: FciBuilderWrapper::Borrowed(fci),
        }
    }

    /// Constructs a [`TransportFeedbackBuilder`] which owns the provided [`FciBuilder`].
    ///
    /// This allows returning it from a function.
    ///
    /// **Warning:** this causes the [`FciBuilder`] to be heap-allocated.
    /// Use [`TransportFeedback::builder`] when possible.
    pub fn builder_owned(
        fci: impl FciBuilder<'static> + 'static,
    ) -> TransportFeedbackBuilder<'static> {
        TransportFeedbackBuilder {
            padding: 0,
            sender_ssrc: 0,
            media_ssrc: 0,
            fci: FciBuilderWrapper::Owned(Box::new(fci)),
        }
    }

    pub fn padding(&self) -> Option<u8> {
        parser::parse_padding(self.data)
    }

    pub fn sender_ssrc(&self) -> u32 {
        parser::parse_ssrc(self.data)
    }

    pub fn media_ssrc(&self) -> u32 {
        parser::parse_ssrc(&self.data[4..])
    }

    pub fn parse_fci<F: FciParser<'a>>(&self) -> Result<F, RtcpParseError> {
        if F::PACKET_TYPE & FciFeedbackPacketType::TRANSPORT == FciFeedbackPacketType::NONE {
            return Err(RtcpParseError::WrongImplementation);
        }
        if parser::parse_count(self.data) != F::FCI_FORMAT {
            return Err(RtcpParseError::WrongImplementation);
        }
        F::parse(&self.data[12..])
    }
}

/// TransportFeedback packet builder
#[derive(Debug)]
#[must_use = "The builder must be built to be used"]
pub struct TransportFeedbackBuilder<'a> {
    padding: u8,
    sender_ssrc: u32,
    media_ssrc: u32,
    fci: FciBuilderWrapper<'a>,
}

impl<'a> TransportFeedbackBuilder<'a> {
    pub fn sender_ssrc(mut self, sender_ssrc: u32) -> Self {
        self.sender_ssrc = sender_ssrc;
        self
    }

    pub fn media_ssrc(mut self, media_ssrc: u32) -> Self {
        self.media_ssrc = media_ssrc;
        self
    }

    /// Sets the number of padding bytes to use for this TransportFeedback packet.
    pub fn padding(mut self, padding: u8) -> Self {
        self.padding = padding;
        self
    }
}

#[inline]
fn fb_write_into<T: RtcpPacket>(
    feedback_type: FciFeedbackPacketType,
    buf: &mut [u8],
    sender_ssrc: u32,
    media_ssrc: u32,
    fci: &dyn FciBuilder,
    padding: u8,
) -> usize {
    if feedback_type & fci.supports_feedback_type() == FciFeedbackPacketType::NONE {
        return 0;
    }

    let fmt = fci.format();
    assert!(fmt <= 0x1f);
    let mut idx = writer::write_header_unchecked::<T>(padding, fmt, buf);

    let mut end = idx;
    end += 4;
    buf[idx..end].copy_from_slice(&sender_ssrc.to_be_bytes());
    idx = end;
    end += 4;
    buf[idx..end].copy_from_slice(&media_ssrc.to_be_bytes());
    idx = end;

    end += fci.write_into_unchecked(&mut buf[idx..]);

    end += writer::write_padding_unchecked(padding, &mut buf[idx..]);

    end
}

impl<'a> RtcpPacketWriter for TransportFeedbackBuilder<'a> {
    /// Calculates the size required to write this TransportFeedback packet.
    ///
    /// Returns an error if:
    ///
    /// * The FCI data is too large
    /// * The FCI fails to calculate a valid size
    fn calculate_size(&self) -> Result<usize, RtcpWriteError> {
        writer::check_padding(self.padding)?;

        if self.fci.supports_feedback_type() & FciFeedbackPacketType::TRANSPORT
            == FciFeedbackPacketType::NONE
        {
            return Err(RtcpWriteError::FciWrongFeedbackPacketType);
        }
        let fci_len = self.fci.calculate_size()?;

        Ok(TransportFeedback::MIN_PACKET_LEN + pad_to_4bytes(fci_len))
    }

    /// Write this TransportFeedback packet data into `buf` without any validity checks.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Panic
    ///
    /// Panics if the buf is not large enough.
    #[inline]
    fn write_into_unchecked(&self, buf: &mut [u8]) -> usize {
        fb_write_into::<TransportFeedback>(
            FciFeedbackPacketType::TRANSPORT,
            buf,
            self.sender_ssrc,
            self.media_ssrc,
            self.fci.as_ref(),
            self.padding,
        )
    }

    fn get_padding(&self) -> Option<u8> {
        if self.padding == 0 {
            return None;
        }

        Some(self.padding)
    }
}

/// A parsed (Transport) Feedback packet as specified in RFC 4585.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadFeedback<'a> {
    data: &'a [u8],
}

impl<'a> RtcpPacket for PayloadFeedback<'a> {
    const MIN_PACKET_LEN: usize = 12;
    const PACKET_TYPE: u8 = 206;
}

impl<'a> RtcpPacketParser<'a> for PayloadFeedback<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        parser::check_packet::<Self>(data)?;
        Ok(Self { data })
    }

    #[inline(always)]
    fn header_data(&self) -> [u8; 4] {
        self.data[..4].try_into().unwrap()
    }
}

impl<'a> PayloadFeedback<'a> {
    /// Constructs a [`PayloadFeedbackBuilder`] which refers to the provided [`FciBuilder`].
    ///
    /// Use [`PayloadFeedback::builder_owned`] to return the [`PayloadFeedbackBuilder`] from a function.
    pub fn builder(fci: &'a dyn FciBuilder<'a>) -> PayloadFeedbackBuilder<'a> {
        PayloadFeedbackBuilder {
            padding: 0,
            sender_ssrc: 0,
            media_ssrc: 0,
            fci: FciBuilderWrapper::Borrowed(fci),
        }
    }

    /// Constructs a [`PayloadFeedbackBuilder`] which owns the provided [`FciBuilder`].
    ///
    /// This allows returning it from a function.
    ///
    /// **Warning:** this causes the [`FciBuilder`] to be heap-allocated.
    /// Use [`PayloadFeedback::builder`] when possible.
    pub fn builder_owned(
        fci: impl FciBuilder<'static> + 'static,
    ) -> PayloadFeedbackBuilder<'static> {
        PayloadFeedbackBuilder {
            padding: 0,
            sender_ssrc: 0,
            media_ssrc: 0,
            fci: FciBuilderWrapper::Owned(Box::new(fci)),
        }
    }

    pub fn padding(&self) -> Option<u8> {
        parser::parse_padding(self.data)
    }

    pub fn sender_ssrc(&self) -> u32 {
        parser::parse_ssrc(self.data)
    }

    pub fn media_ssrc(&self) -> u32 {
        parser::parse_ssrc(&self.data[4..])
    }

    pub fn parse_fci<F: FciParser<'a>>(&self) -> Result<F, RtcpParseError> {
        if F::PACKET_TYPE & FciFeedbackPacketType::PAYLOAD == FciFeedbackPacketType::NONE {
            return Err(RtcpParseError::WrongImplementation);
        }
        if parser::parse_count(self.data) != F::FCI_FORMAT {
            return Err(RtcpParseError::WrongImplementation);
        }
        F::parse(&self.data[12..])
    }
}

/// TransportFeedback packet builder
#[derive(Debug)]
#[must_use = "The builder must be built to be used"]
pub struct PayloadFeedbackBuilder<'a> {
    padding: u8,
    sender_ssrc: u32,
    media_ssrc: u32,
    fci: FciBuilderWrapper<'a>,
}

impl<'a> PayloadFeedbackBuilder<'a> {
    pub fn sender_ssrc(mut self, sender_ssrc: u32) -> Self {
        self.sender_ssrc = sender_ssrc;
        self
    }

    pub fn media_ssrc(mut self, media_ssrc: u32) -> Self {
        self.media_ssrc = media_ssrc;
        self
    }

    /// Sets the number of padding bytes to use for this TransportFeedback packet.
    pub fn padding(mut self, padding: u8) -> Self {
        self.padding = padding;
        self
    }
}

impl<'a> RtcpPacketWriter for PayloadFeedbackBuilder<'a> {
    /// Calculates the size required to write this PayloadFeedback packet.
    ///
    /// Returns an error if:
    ///
    /// * The FCI data is too large
    /// * The FCI fails to calculate a valid size
    fn calculate_size(&self) -> Result<usize, RtcpWriteError> {
        writer::check_padding(self.padding)?;

        if self.fci.supports_feedback_type() & FciFeedbackPacketType::PAYLOAD
            == FciFeedbackPacketType::NONE
        {
            return Err(RtcpWriteError::FciWrongFeedbackPacketType);
        }
        let fci_len = self.fci.calculate_size()?;

        Ok(PayloadFeedback::MIN_PACKET_LEN + pad_to_4bytes(fci_len))
    }

    /// Write this TransportFeedback packet data into `buf` without any validity checks.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Panic
    ///
    /// Panics if the buf is not large enough.
    #[inline]
    fn write_into_unchecked(&self, buf: &mut [u8]) -> usize {
        fb_write_into::<PayloadFeedback>(
            FciFeedbackPacketType::PAYLOAD,
            buf,
            self.sender_ssrc,
            self.media_ssrc,
            self.fci.as_ref(),
            self.padding,
        )
    }

    fn get_padding(&self) -> Option<u8> {
        if self.padding == 0 {
            return None;
        }

        Some(self.padding)
    }
}

pub trait FciParser<'a>: Sized {
    const PACKET_TYPE: FciFeedbackPacketType;
    const FCI_FORMAT: u8;

    /// Parse the provided FCI data
    fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError>;
}

/// Stack or heap allocated [`FciBuilder`] wrapper.
///
/// This wrapper allows borrowing or owning an [`FciBuilder`] without
/// propagating the concrete type of the [`FciBuilder`] to types such as
/// [`PayloadFeedbackBuilder`] or [`TransportFeedback`]. This is needed for
/// these types to be included in collections such as [`crate::CompoundBuilder`].
///
/// `Cow` from `std` would not be suitable here because it would require
/// declaring the `B` type parameter as an implementer of `ToOwned`,
/// which is not object-safe.
#[derive(Debug)]
enum FciBuilderWrapper<'a> {
    Borrowed(&'a dyn FciBuilder<'a>),
    // Note: using `'a` and not `'static` here to help with the implementations
    // of `deref()` and `as_ref()`. This enum is private and the `Owned` variant
    // can only be constructed from `PayloadFeedbackBuilder::builder_owned` &
    // `TransportFeedback::builder_owned` which constrain the `FciBuilder` to be `'static`.
    Owned(Box<dyn FciBuilder<'a>>),
}

impl<'a, T: FciBuilder<'a>> From<&'a T> for FciBuilderWrapper<'a> {
    fn from(value: &'a T) -> Self {
        FciBuilderWrapper::Borrowed(value)
    }
}

impl<'a> std::convert::AsRef<dyn FciBuilder<'a> + 'a> for FciBuilderWrapper<'a> {
    fn as_ref(&self) -> &(dyn FciBuilder<'a> + 'a) {
        match self {
            FciBuilderWrapper::Borrowed(this) => *this,
            FciBuilderWrapper::Owned(this) => this.borrow(),
        }
    }
}

impl<'a> std::ops::Deref for FciBuilderWrapper<'a> {
    type Target = dyn FciBuilder<'a> + 'a;

    fn deref(&self) -> &(dyn FciBuilder<'a> + 'a) {
        match self {
            FciBuilderWrapper::Borrowed(this) => *this,
            FciBuilderWrapper::Owned(this) => this.borrow(),
        }
    }
}

pub trait FciBuilder<'a>: RtcpPacketWriter {
    /// The format field value to place in the RTCP header
    fn format(&self) -> u8;
    fn supports_feedback_type(&self) -> FciFeedbackPacketType;
}
