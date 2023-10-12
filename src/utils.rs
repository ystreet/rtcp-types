// SPDX-License-Identifier: MIT OR Apache-2.0

#[track_caller]
#[inline(always)]
pub(crate) fn u16_from_be_bytes(bytes: &[u8]) -> u16 {
    u16::from_be_bytes(bytes.try_into().expect("expecting 2 bytes"))
}

#[track_caller]
#[inline(always)]
pub(crate) fn u32_from_be_bytes(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().expect("expecting 4 bytes"))
}

#[track_caller]
#[inline(always)]
pub(crate) fn u64_from_be_bytes(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().expect("expecting 8 bytes"))
}
