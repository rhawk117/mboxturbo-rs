//! The entry cache: directory entries parsed once, packed into atomic cells.

use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};

use super::codec;

/// A directory entry parsed once, kept so later reads of its block skip the parse. An entry of
/// the original bytes is kept only after its block passed its checksum. It keeps the frame and
/// the payload start; the payload range is bounded at each read by [`Parsed::payload`].
#[derive(Debug, Clone, Copy)]
pub(super) struct Parsed {
    /// Base, flags and width of the block.
    frame: codec::Frame,
    /// Where the block's payload starts in the index bytes.
    payload: usize,
}

impl Parsed {
    /// Base, flags and width of the block.
    pub(super) const fn frame(&self) -> &codec::Frame {
        &self.frame
    }

    /// The entry `Layout::entry_at` read, without its checksum.
    pub(super) const fn new((block, payload): (codec::Block, Range<usize>)) -> Self {
        Self {
            frame: block.frame(),
            payload: payload.start,
        }
    }

    /// The block's payload of `len` bytes in `bytes`, `None` when it lies past their end.
    #[inline]
    pub(super) fn payload<'bytes>(&self, bytes: &'bytes [u8], len: usize) -> Option<&'bytes [u8]> {
        bytes.get(self.payload..self.payload.checked_add(len)?)
    }

    /// Start at `index` of the block, as [`codec::Frame::start_at`] reads it from `bytes`.
    #[inline]
    pub(super) fn start(&self, bytes: &[u8], index: usize) -> Option<u64> {
        self.frame.start_at(bytes, self.payload, index)
    }

    /// Starts at `index` and `index + 1` of the block, as [`codec::Frame::start_pair_at`]
    /// reads them from `bytes`.
    #[inline]
    pub(super) fn start_pair(&self, bytes: &[u8], index: usize) -> Option<(u64, u64)> {
        self.frame.start_pair_at(bytes, self.payload, index)
    }
}

/// One slot of an entry cache: a [`Parsed`] packed into two atomic words, empty while both are
/// zero so a table of them is zero-filled at open. `word` holds, from the top, a filled bit,
/// the flags, the width and the payload start.
#[derive(Debug)]
pub(super) struct Cell {
    /// The block's base; meaningful once `word` has its filled bit.
    base: AtomicU64,
    /// Filled bit, flags, width and payload start, zero while empty.
    word: AtomicU64,
}

impl Cell {
    /// Bit set in `word` once the cell holds an entry.
    const FILLED: u64 = 1 << 63;
    /// Bit where the flags begin.
    const FLAGS_AT: u32 = Self::START_BITS + Self::WIDTH_BITS;
    /// Bits of the payload start.
    const START_BITS: u32 = 48;
    /// Mask of the payload start.
    const START_MASK: u64 = (1 << Self::START_BITS) - 1;
    /// Bits of the width.
    const WIDTH_BITS: u32 = 7;
    /// Mask of the width, once shifted down.
    const WIDTH_MASK: u64 = (1 << Self::WIDTH_BITS) - 1;

    /// A cell holding nothing.
    pub(super) const fn empty() -> Self {
        Self {
            base: AtomicU64::new(0),
            word: AtomicU64::new(0),
        }
    }

    /// Whether an entry was stored.
    #[cfg(test)]
    #[inline]
    pub(super) fn is_filled(&self) -> bool {
        self.word.load(Ordering::Relaxed) & Self::FILLED != 0
    }

    /// The stored entry, `None` while the cell is empty.
    #[inline]
    pub(super) fn load(&self) -> Option<Parsed> {
        let word = self.word.load(Ordering::Acquire);
        if word & Self::FILLED == 0 {
            return None;
        }
        let base = self.base.load(Ordering::Relaxed);
        let raw_flags = u8::try_from(word.checked_shr(Self::FLAGS_AT)? & 0xFF);
        let raw_width = u8::try_from(word.checked_shr(Self::START_BITS)? & Self::WIDTH_MASK);
        let raw_start = usize::try_from(word & Self::START_MASK);
        let (Ok(flags), Ok(width), Ok(payload)) = (raw_flags, raw_width, raw_start) else {
            return None;
        };
        Some(Parsed {
            frame: codec::Frame { base, flags, width },
            payload,
        })
    }

    /// Stores `parsed`, `None` and nothing stored when its width or payload start does not fit.
    /// Threads filling one cell store the same bits, taken from one verified entry.
    pub(super) fn store(&self, parsed: Parsed) -> Option<()> {
        let start = u64::try_from(parsed.payload)
            .map_or(None, |start| (start <= Self::START_MASK).then_some(start))?;
        let width =
            Some(u64::from(parsed.frame.width)).filter(|width| *width <= Self::WIDTH_MASK)?;
        let flags = u64::from(parsed.frame.flags).checked_shl(Self::FLAGS_AT)?;
        let word = Self::FILLED | flags | width.checked_shl(Self::START_BITS)? | start;
        self.base.store(parsed.frame.base, Ordering::Relaxed);
        self.word.store(word, Ordering::Release);
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::codec;
    use super::{Cell, Parsed};

    #[test]
    fn a_cached_entry_costs_at_most_sixteen_bytes_per_block() {
        assert!(
            size_of::<Cell>() <= 16,
            "the open path adds one cell per block and section beside the mapping"
        );
    }

    #[test]
    fn a_cell_round_trips_the_largest_entry() {
        let cell = Cell::empty();
        assert!(cell.load().is_none(), "an empty cell loads nothing");
        let largest = (1_usize << 48_u32) - 1;
        let parsed = Parsed {
            frame: codec::Frame {
                base: u64::MAX,
                flags: 0xFF,
                width: 64,
            },
            payload: largest,
        };
        assert!(cell.store(parsed).is_some(), "the largest start fits");
        let loaded = cell.load().expect("a filled cell loads");
        assert_eq!(
            (
                loaded.frame.base,
                loaded.frame.flags,
                loaded.frame.width,
                loaded.payload
            ),
            (u64::MAX, 0xFF, 64, largest)
        );
        assert!(cell.is_filled(), "a stored cell counts as filled");
    }

    #[test]
    fn a_cell_refuses_a_payload_start_of_two_to_the_forty_eighth() {
        let cell = Cell::empty();
        let parsed = Parsed {
            frame: codec::Frame {
                base: 0,
                flags: 0,
                width: 0,
            },
            payload: 1_usize << 48_u32,
        };
        assert!(cell.store(parsed).is_none(), "the start does not fit");
        assert!(!cell.is_filled(), "a refused store leaves the cell empty");
    }

    #[test]
    fn a_cell_refuses_a_width_above_127() {
        let cell = Cell::empty();
        let parsed = Parsed {
            frame: codec::Frame {
                base: 0,
                flags: 0,
                width: 128,
            },
            payload: 8,
        };
        assert!(cell.store(parsed).is_none(), "the width does not fit");
        assert!(!cell.is_filled(), "a refused store leaves the cell empty");
        assert!(cell.load().is_none(), "a refused store loads nothing");
    }
}
