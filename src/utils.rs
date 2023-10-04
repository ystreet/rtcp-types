// SPDX-License-Identifier: MIT OR Apache-2.0

pub(crate) fn u16_from_be_bytes(bytes: &[u8]) -> u16 {
    (bytes[0] as u16) << 8 | bytes[1] as u16
}

pub(crate) fn u32_from_be_bytes(bytes: &[u8]) -> u32 {
    (bytes[0] as u32) << 24 | (bytes[1] as u32) << 16 | (bytes[2] as u32) << 8 | bytes[3] as u32
}

pub(crate) fn u64_from_be_bytes(bytes: &[u8]) -> u64 {
    (bytes[0] as u64) << 56
        | (bytes[1] as u64) << 48
        | (bytes[2] as u64) << 40
        | (bytes[3] as u64) << 32
        | (bytes[4] as u64) << 24
        | (bytes[5] as u64) << 16
        | (bytes[6] as u64) << 8
        | bytes[7] as u64
}
