//! How many messages one block of the index covers, and the one range of sizes the file header
//! can describe.

/// How many messages one block of the index covers: a power of two from 2 to 65536.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockSize(u8);

impl BlockSize {
    /// Block shift of the default size: 256 messages.
    const DEFAULT_SHIFT: u8 = 8;
    /// Largest block shift the file header can describe.
    pub(crate) const MAX_SHIFT: u8 = 16;
    /// Smallest block shift the file header can describe.
    pub(crate) const MIN_SHIFT: u8 = 1;

    /// The number of messages in one block.
    #[must_use]
    pub const fn entries(self) -> usize {
        #[expect(
            clippy::as_conversions,
            reason = "widening a shift of at most 16 to u32 cannot lose bits"
        )]
        let shift = self.0 as u32;
        1_usize << shift
    }

    /// The block of `2^shift` messages, or `None` when `shift` is below [`BlockSize::MIN_SHIFT`]
    /// or above [`BlockSize::MAX_SHIFT`].
    ///
    /// The header reader calls this on the shift byte it finds in a file, so a header that
    /// declares a block the format cannot describe is refused instead of trusted.
    pub(crate) const fn from_shift(shift: u8) -> Option<Self> {
        if matches!(shift, Self::MIN_SHIFT..=Self::MAX_SHIFT) {
            Some(Self(shift))
        } else {
            None
        }
    }

    /// The number of messages in one block, as the `u64` the header arithmetic uses.
    pub(crate) const fn messages(self) -> u64 {
        #[expect(
            clippy::as_conversions,
            reason = "widening a shift of at most 16 to u32 cannot lose bits"
        )]
        let shift = self.0 as u32;
        1_u64 << shift
    }

    /// A block of `entries` messages, or `None` unless `entries` is a power of two between 2 and
    /// 65536 inclusive, the range the index file header can describe.
    #[must_use]
    pub const fn new(entries: usize) -> Option<Self> {
        if !entries.is_power_of_two() {
            return None;
        }
        #[expect(
            clippy::cast_possible_truncation,
            clippy::as_conversions,
            reason = "entries is a power of two, so its shift is at most 63"
        )]
        let shift = entries.trailing_zeros() as u8;
        Self::from_shift(shift)
    }

    /// The header's block shift: `entries()` is `1 << shift()`.
    pub(crate) const fn shift(self) -> u8 {
        self.0
    }
}

impl Default for BlockSize {
    /// 256 messages per block: small enough that touching one message decodes little, large
    /// enough that the directory stays a small share of the file.
    fn default() -> Self {
        Self(Self::DEFAULT_SHIFT)
    }
}
