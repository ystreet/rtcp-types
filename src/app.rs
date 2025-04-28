// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    prelude::*,
    utils::{parser, writer},
    RtcpPacket, RtcpParseError, RtcpWriteError,
};

/// A Parsed App packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct App<'a> {
    data: &'a [u8],
}

impl RtcpPacket for App<'_> {
    const MIN_PACKET_LEN: usize = 12;
    const PACKET_TYPE: u8 = 204;
}

impl<'a> RtcpPacketParser<'a> for App<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        parser::check_packet::<Self>(data)?;

        Ok(Self { data })
    }

    #[inline(always)]
    fn header_data(&self) -> [u8; 4] {
        self.data[..4].try_into().unwrap()
    }
}

impl<'a> App<'a> {
    const SUBTYPE_MASK: u8 = Self::MAX_COUNT;
    /// The length of the name of an [`App`] packet.
    pub const NAME_LEN: usize = 4;

    /// The (optional) padding used by this [`App`] packet
    pub fn padding(&self) -> Option<u8> {
        parser::parse_padding(self.data)
    }

    /// The SSRC this [`App`] packet refers to
    pub fn ssrc(&self) -> u32 {
        parser::parse_ssrc(self.data)
    }

    /// The `name` for this [`App`] packet.  The `name` should be a sequence of 4 ASCII
    /// characters.
    pub fn name(&self) -> [u8; App::NAME_LEN] {
        self.data[8..8 + Self::NAME_LEN].try_into().unwrap()
    }

    /// The `name` for this [`App`] as a string.
    pub fn get_name_string(&self) -> Result<String, std::string::FromUtf8Error> {
        // name is fixed length potentially zero terminated
        String::from_utf8(Vec::from_iter(self.name().iter().map_while(|&b| {
            if b == 0 {
                None
            } else {
                Some(b)
            }
        })))
    }

    /// The application specific data
    pub fn data(&self) -> &[u8] {
        &self.data[12..self.data.len() - self.padding().unwrap_or(0) as usize]
    }

    /// Constructs an [`AppBuilder`].
    ///
    /// `name` must be "a sequence of four ASCII characters".
    pub fn builder(ssrc: u32, name: &'a str) -> AppBuilder<'a> {
        AppBuilder::new(ssrc, name)
    }
}

/// App packet Builder
#[derive(Debug)]
#[must_use = "The builder must be built to be used"]
pub struct AppBuilder<'a> {
    ssrc: u32,
    padding: u8,
    subtype: u8,
    name: &'a str,
    data: &'a [u8],
}

impl<'a> AppBuilder<'a> {
    fn new(ssrc: u32, name: &'a str) -> Self {
        AppBuilder {
            ssrc,
            padding: 0,
            subtype: 0,
            name,
            data: &[],
        }
    }

    /// Sets the number of padding bytes to use for this App.
    pub fn padding(mut self, padding: u8) -> Self {
        self.padding = padding;
        self
    }

    /// The subtype to use for this [`App`] packet
    pub fn subtype(mut self, subtype: u8) -> Self {
        self.subtype = subtype;
        self
    }

    /// The data to use for this [`App`] packet
    pub fn data(mut self, data: &'a [u8]) -> Self {
        self.data = data;
        self
    }
}

impl RtcpPacketWriter for AppBuilder<'_> {
    /// Calculates the size required to write this App packet.
    ///
    /// Returns an error if:
    ///
    /// * The subtype is out of range.
    /// * The name is not a sequence of four ASCII characters.
    /// * The data length is not a multiple of 4.
    /// * The padding is not a multiple of 4.
    #[inline]
    fn calculate_size(&self) -> Result<usize, RtcpWriteError> {
        if self.subtype > App::SUBTYPE_MASK {
            return Err(RtcpWriteError::AppSubtypeOutOfRange {
                subtype: self.subtype,
                max: App::SUBTYPE_MASK,
            });
        }

        // Note: RFC 3550 p. 44 is ambiguous whether the name MUST consists in
        // 4 non-zero ASCII character or if it could be shorter with the rest
        // of the 4 bytes filled with 0. We decided to allow filling with 0
        // for flexility reasons.
        if self.name.len() > App::NAME_LEN || !self.name.is_ascii() {
            return Err(RtcpWriteError::InvalidName);
        }

        let mut size = App::MIN_PACKET_LEN + self.padding as usize;

        if self.data.len() % 4 != 0 {
            return Err(RtcpWriteError::DataLen32bitMultiple(self.data.len()));
        }

        size += self.data.len();

        writer::check_padding(self.padding)?;

        Ok(size)
    }

    /// Writes this App packet specific data into `buf` without any validity checks.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Panic
    ///
    /// Panics if the buf is not large enough.
    #[inline]
    fn write_into_unchecked(&self, buf: &mut [u8]) -> usize {
        writer::write_header_unchecked::<App>(self.padding, self.subtype, buf);

        buf[4..8].copy_from_slice(&self.ssrc.to_be_bytes());

        let name = self.name.as_bytes();
        let name_len = name.len();
        let mut end = 8 + name_len;
        buf[8..end].copy_from_slice(name);
        // See note in calculate_size()
        if end < 12 {
            buf[end..12].fill(0);
        }

        end = 12 + self.data.len();
        buf[12..end].copy_from_slice(self.data);

        end += writer::write_padding_unchecked(self.padding, &mut buf[end..]);

        end
    }

    fn get_padding(&self) -> Option<u8> {
        if self.padding == 0 {
            return None;
        }

        Some(self.padding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_app() {
        let data = [
            0x80, 0xcc, 0x00, 0x02, 0x91, 0x82, 0x73, 0x64, 0x00, 0x00, 0x00, 0x00,
        ];
        let app = App::parse(&data).unwrap();
        assert_eq!(app.version(), 2);
        assert_eq!(app.padding(), None);
        assert_eq!(app.subtype(), 0);
        assert_eq!(app.name(), [0, 0, 0, 0]);
        assert!(app.get_name_string().unwrap().is_empty());
        assert!(app.data().is_empty());
    }

    #[test]
    fn build_empty_app() {
        const REQ_LEN: usize = App::MIN_PACKET_LEN;
        let appb = App::builder(0x91827364, "name");
        let req_len = appb.calculate_size().unwrap();
        assert_eq!(req_len, REQ_LEN);

        let mut data = [0; REQ_LEN];
        let len = appb.write_into(&mut data).unwrap();

        assert_eq!(len, REQ_LEN);
        assert_eq!(
            data,
            [0x80, 0xcc, 0x00, 0x02, 0x91, 0x82, 0x73, 0x64, 0x6e, 0x61, 0x6d, 0x65,]
        );
    }

    #[test]
    fn parse_app() {
        let data = [
            0xbf, 0xcc, 0x00, 0x04, 0x91, 0x82, 0x73, 0x64, 0x6e, 0x61, 0x6d, 0x65, 0x01, 0x02,
            0x03, 0x00, 0x00, 0x00, 0x00, 0x04,
        ];
        let app = App::parse(&data).unwrap();
        assert_eq!(app.version(), 2);
        assert_eq!(app.padding(), Some(4));
        assert_eq!(app.subtype(), 31);
        assert_eq!(app.name(), "name".as_bytes());
        assert_eq!(app.get_name_string().unwrap(), "name");
        assert_eq!(app.data(), [0x01, 0x02, 0x3, 0x0]);
    }

    #[test]
    fn build_app() {
        const REQ_LEN: usize = App::MIN_PACKET_LEN + 4 + 4;
        let appb = App::builder(0x91827364, "name")
            .padding(4)
            .subtype(31)
            .data(&[0x01, 0x02, 0x3, 0x0]);
        let req_len = appb.calculate_size().unwrap();
        assert_eq!(req_len, REQ_LEN);

        let mut data = [0; REQ_LEN];
        let len = appb.write_into(&mut data).unwrap();
        assert_eq!(len, REQ_LEN);
        assert_eq!(
            data,
            [
                0xbf, 0xcc, 0x00, 0x04, 0x91, 0x82, 0x73, 0x64, 0x6e, 0x61, 0x6d, 0x65, 0x01, 0x02,
                0x03, 0x00, 0x00, 0x00, 0x00, 0x04,
            ]
        );
    }

    #[test]
    fn build_short_name() {
        const REQ_LEN: usize = App::MIN_PACKET_LEN;
        let appb = App::builder(0x91827364, "nam").subtype(31);
        let req_len = appb.calculate_size().unwrap();
        assert_eq!(req_len, REQ_LEN);

        let mut data = [0; REQ_LEN];
        let len = appb.write_into(&mut data).unwrap();
        assert_eq!(len, REQ_LEN);
        assert_eq!(
            data,
            [0x9f, 0xcc, 0x00, 0x02, 0x91, 0x82, 0x73, 0x64, 0x6e, 0x61, 0x6d, 0x00]
        );
    }

    #[test]
    fn build_subtype_out_of_range() {
        let b = App::builder(0x91827364, "name").subtype(0x1f + 1);
        let err = b.calculate_size().unwrap_err();
        assert_eq!(
            err,
            RtcpWriteError::AppSubtypeOutOfRange {
                subtype: 0x1f + 1,
                max: App::SUBTYPE_MASK
            }
        );
    }

    #[test]
    fn build_invalid_name_too_large() {
        let b = App::builder(0x91827364, "name_");
        let err = b.calculate_size().unwrap_err();
        assert_eq!(err, RtcpWriteError::InvalidName);
    }

    #[test]
    fn build_invalid_non_ascii_name() {
        let b = App::builder(0x91827364, "nąm");
        let err = b.calculate_size().unwrap_err();
        assert_eq!(err, RtcpWriteError::InvalidName);
    }

    #[test]
    fn build_data_len_not_32bits_multiple() {
        let b = App::builder(0x91827364, "name").data(&[0x01, 0x02, 0x3]);
        let err = b.calculate_size().unwrap_err();
        assert_eq!(err, RtcpWriteError::DataLen32bitMultiple(3));
    }

    #[test]
    fn build_padding_not_multiple_4() {
        let b = App::builder(0x91827364, "name").padding(5);
        let err = b.calculate_size().unwrap_err();
        assert_eq!(err, RtcpWriteError::InvalidPadding { padding: 5 });
    }
}
