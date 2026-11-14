//! The cursor that walks starts blocks in order, caching the two it read last.

use std::mem;
use std::ops::Range;

use super::Index;
use crate::width::narrow;

/// One decoded starts block held by a [`Cursor`].
#[derive(Debug, Default)]
struct Slot {
    /// The block the starts belong to, or `None` while the slot holds nothing decoded.
    block: Option<usize>,
    /// The start of every message in the block, then where its last message ends: the next
    /// block's first start or the mailbox length. Ascending and inside the mapping, or empty
    /// when the decoded block breaks either rule; reused across refills.
    bounds: Vec<u64>,
    /// Position of the block's first message.
    first: usize,
}

impl Slot {
    /// Byte range of the message at `position`, or `None` when it is not in the slot's block or
    /// the slot holds no usable bounds.
    #[inline]
    fn span(&self, position: usize) -> Option<Range<usize>> {
        let within = position.checked_sub(self.first)?;
        let &[start, end] = self.bounds.get(within..)?.first_chunk::<2>()?;
        Some(narrow(start)?..narrow(end)?)
    }
}

/// Answers [`Index::span`] for positions walked in order, decoding each starts block once.
///
/// The cursor keeps the two blocks it read last, so a pass from either end, or from both ends
/// at once, decodes each block once or twice at most. Anything it cannot answer from a verified
/// block, and every answer once the index has been rebuilt, goes through [`Index::span`].
#[derive(Debug)]
pub(crate) struct Cursor<'index> {
    /// The index being walked.
    index: &'index Index,
    /// The newest block, then the one before it.
    slots: (Slot, Slot),
}

impl Cursor<'_> {
    /// The span of `position` from the newest block, else from the block holding it once it
    /// is the newest, `None` when they cannot answer it.
    #[inline]
    fn cached(&mut self, position: usize) -> Option<Range<usize>> {
        if self.index.replacement.get().is_some() {
            return None;
        }
        self.slots
            .0
            .span(position)
            .or_else(|| self.refill(position))
    }

    /// A cursor over `index` that has decoded nothing yet.
    pub(super) const fn new(index: &Index) -> Cursor<'_> {
        Cursor {
            index,
            slots: (
                Slot {
                    block: None,
                    bounds: Vec::new(),
                    first: 0,
                },
                Slot {
                    block: None,
                    bounds: Vec::new(),
                    first: 0,
                },
            ),
        }
    }

    /// Makes the block holding `position` the newest slot, decoding it unless one of the slots
    /// holds it, and answers the span of `position` from it.
    #[inline(never)]
    fn refill(&mut self, position: usize) -> Option<Range<usize>> {
        let (block, within) = self.index.layout.place(position)?;
        if self.slots.0.block != Some(block) {
            mem::swap(&mut self.slots.0, &mut self.slots.1);
        }
        if self.slots.0.block != Some(block) {
            let slot = &mut self.slots.0;
            slot.block = None;
            slot.bounds.clear();
            slot.first = position.checked_sub(within)?;
            if self.index.decode(block, &mut slot.bounds).is_none() {
                slot.bounds.clear();
                return None;
            }
            slot.block = Some(block);
        }
        self.slots.0.span(position)
    }

    /// Byte range of the message at `position`, answering exactly what [`Index::span`] does.
    #[inline]
    pub(crate) fn span(&mut self, position: usize) -> Option<Range<usize>> {
        self.cached(position)
            .or_else(|| self.index.checked_span(position))
    }
}
