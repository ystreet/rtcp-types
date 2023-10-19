// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{
    utils::{parser::*, writer::*},
    RtcpPacket, RtcpParseError, RtcpWriteError,
};

/// A Parsed App packet.
#[derive(Debug, PartialEq, Eq)]
pub struct App<'a> {
    data: &'a [u8],
}

impl<'a> RtcpPacket for App<'a> {
    const MIN_PACKET_LEN: usize = 12;
    const PACKET_TYPE: u8 = 204;
}

impl<'a> App<'a> {
    const SUBTYPE_MASK: u8 = Self::MAX_COUNT;
    pub const NAME_LEN: usize = 4;

    pub fn parse(data: &'a [u8]) -> Result<Self, RtcpParseError> {
        check_packet::<Self>(data)?;

        Ok(Self { data })
    }

    pub fn padding(&self) -> Option<u8> {
        parse_padding(self.data)
    }

    pub fn version(&self) -> u8 {
        parse_version(self.data)
    }

    pub fn subtype(&self) -> u8 {
        parse_count(self.data)
    }

    pub fn length(&self) -> usize {
        parse_length(self.data)
    }

    pub fn ssrc(&self) -> u32 {
        parse_ssrc(self.data)
    }

    pub fn name(&self) -> [u8; App::NAME_LEN] {
        self.data[8..8 + Self::NAME_LEN].try_into().unwrap()
    }

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

    pub fn data(&self) -> &[u8] {
        &self.data[12..self.data.len() - self.padding().unwrap_or(0) as usize]
    }

    pub fn builder(ssrc: u32) -> AppBuilder {
        AppBuilder::new(ssrc)
    }
}

/// App packet Builder
#[derive(Debug)]
pub struct AppBuilder {
    ssrc: u32,
    padding: u8,
    subtype: u8,
    name: Vec<u8>,
    data: Vec<u8>,
}

impl AppBuilder {
    fn new(ssrc: u32) -> Self {
        AppBuilder {
            ssrc,
            padding: 0,
            subtype: 0,
            name: Vec::new(),
            data: Vec::new(),
        }
    }

    /// Sets the number of padding bytes to use for this App.
    pub fn padding(mut self, padding: u8) -> Self {
        self.padding = padding;
        self
    }

    pub fn get_padding(&self) -> u8 {
        self.padding
    }

    pub fn subtype(mut self, subtype: u8) -> Self {
        self.subtype = subtype;
        self
    }

    pub fn raw_name(mut self, name: impl Into<Vec<u8>>) -> Self {
        self.name = name.into();
        self
    }

    pub fn name(mut self, name: &str) -> Self {
        self.name = name.as_bytes().into();
        self
    }

    pub fn data(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.data = data.into();
        self
    }

    /// Calculates the size required to write this App packet.
    ///
    /// Returns an error if:
    ///
    /// * The subtype is out of range.
    /// * The name len is too large.
    /// * The data length is not a multiple of 4.
    /// * The padding is not a multiple of 4.
    #[inline]
    pub fn calculate_size(&self) -> Result<usize, RtcpWriteError> {
        if self.subtype > App::SUBTYPE_MASK {
            return Err(RtcpWriteError::AppSubtypeOutOfRange {
                subtype: self.subtype,
                max: App::SUBTYPE_MASK,
            });
        }

        if self.name.len() > App::NAME_LEN {
            return Err(RtcpWriteError::NameLenTooLarge {
                len: self.name.len(),
                max: App::NAME_LEN as u8,
            });
        }

        if self.data.len() % 4 != 0 {
            return Err(RtcpWriteError::DataLen32bitMultiple(self.data.len()));
        }

        check_padding(self.padding)?;

        Ok(App::MIN_PACKET_LEN + self.data.len() + self.padding as usize)
    }

    /// Writes this App packet specific data into `buf` without any validity checks.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Panic
    ///
    /// Panics if the buf is not large enough.
    #[inline]
    pub(crate) fn write_into_unchecked(&self, buf: &mut [u8]) -> usize {
        write_header_unchecked::<App>(self.padding, self.subtype, buf);

        buf[4..8].copy_from_slice(&self.ssrc.to_be_bytes());

        let name_len = self.name.len();
        let mut end = 8 + name_len;
        buf[8..end].copy_from_slice(&self.name);
        if end < 12 {
            buf[end..12].fill(0);
        }

        end = 12 + self.data.len();
        buf[12..end].copy_from_slice(&self.data);

        end += write_padding_unchecked(self.padding, &mut buf[end..]);

        end
    }

    /// Writes the App packet into `buf`.
    ///
    /// Returns an error if:
    ///
    /// * The buffer is too small.
    /// * The subtype is out of range.
    /// * The name len is too large.
    /// * The data length is not a multiple of 4.
    /// * The padding is not a multiple of 4.
    pub fn write_into(self, buf: &mut [u8]) -> Result<usize, RtcpWriteError> {
        let req_size = self.calculate_size()?;
        if buf.len() < req_size {
            return Err(RtcpWriteError::OutputTooSmall(req_size));
        }

        Ok(self.write_into_unchecked(&mut buf[..req_size]))
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
        let appb = App::builder(0x91827364);
        let req_len = appb.calculate_size().unwrap();
        assert_eq!(req_len, REQ_LEN);

        let mut data = [0; REQ_LEN];
        let len = appb.write_into(&mut data).unwrap();
        assert_eq!(len, REQ_LEN);
        assert_eq!(
            data,
            [0x80, 0xcc, 0x00, 0x02, 0x91, 0x82, 0x73, 0x64, 0x00, 0x00, 0x00, 0x00]
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
        let appb = App::builder(0x91827364)
            .padding(4)
            .subtype(31)
            .name("abc")
            .data([0x01, 0x02, 0x3, 0x0]);
        let req_len = appb.calculate_size().unwrap();
        assert_eq!(req_len, REQ_LEN);

        let mut data = [0; REQ_LEN];
        let len = appb.write_into(&mut data).unwrap();
        assert_eq!(len, REQ_LEN);
        assert_eq!(
            data,
            [
                0xbf, 0xcc, 0x00, 0x04, 0x91, 0x82, 0x73, 0x64, 0x61, 0x62, 0x63, 0x00, 0x01, 0x02,
                0x03, 0x00, 0x00, 0x00, 0x00, 0x04,
            ]
        );
    }

    #[test]
    fn build_raw_name() {
        const REQ_LEN: usize = App::MIN_PACKET_LEN;
        let appb = App::builder(0x91827364)
            .subtype(31)
            .raw_name("name".as_bytes());
        let req_len = appb.calculate_size().unwrap();
        assert_eq!(req_len, REQ_LEN);

        let mut data = [0; REQ_LEN];
        let len = appb.write_into(&mut data).unwrap();
        assert_eq!(len, REQ_LEN);
        assert_eq!(
            data,
            [0x9f, 0xcc, 0x00, 0x02, 0x91, 0x82, 0x73, 0x64, 0x6e, 0x61, 0x6d, 0x65,]
        );
    }

    #[test]
    fn build_subtype_out_of_range() {
        let b = App::builder(0x91827364).subtype(0x1f + 1);
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
    fn build_name_too_large() {
        let b = App::builder(0x91827364).name("abcdefghi");
        let err = b.calculate_size().unwrap_err();
        assert_eq!(
            err,
            RtcpWriteError::NameLenTooLarge {
                len: 9,
                max: App::NAME_LEN as u8
            }
        );
    }

    #[test]
    fn build_data_len_not_32bits_multiple() {
        let b = App::builder(0x91827364).data([0x01, 0x02, 0x3]);
        let err = b.calculate_size().unwrap_err();
        assert_eq!(err, RtcpWriteError::DataLen32bitMultiple(3));
    }

    #[test]
    fn build_padding_not_multiple_4() {
        let b = App::builder(0x91827364).padding(5);
        let err = b.calculate_size().unwrap_err();
        assert_eq!(err, RtcpWriteError::InvalidPadding { padding: 5 });
    }
}
