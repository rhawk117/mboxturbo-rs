//! Lossless conversions between `usize` and the fixed-width integers used on disk.

const _: () = assert!(usize::BITS <= u64::BITS, "byte offsets are stored as u64");

pub(crate) fn widen(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

pub(crate) fn narrow(value: u64) -> Option<usize> {
    usize::try_from(value).ok()
}
