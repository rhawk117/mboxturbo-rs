//! Lossless conversions between `usize` and the fixed-width integers used on disk.

const _: () = assert!(usize::BITS <= u64::BITS, "byte offsets are stored as u64");

/// Converts a `usize` to the `u64` used on disk; never lossy, because the const assert above
/// guarantees `usize` is no wider than `u64`.
#[expect(
    clippy::disallowed_methods,
    reason = "the const assert on usize::BITS <= u64::BITS makes this conversion infallible"
)]
pub(crate) fn widen(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Converts an on-disk `u64` to `usize`, or `None` when it does not fit (a 32-bit target reading a
/// large offset); callers report that as a corruption (`MailboxTooLarge` or `Bounds`).
#[expect(
    clippy::disallowed_methods,
    reason = "None is the answer: callers map it to Corruption::MailboxTooLarge or \
              Corruption::Bounds, it is not swallowed"
)]
pub(crate) fn narrow(value: u64) -> Option<usize> {
    usize::try_from(value).ok()
}
