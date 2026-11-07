//! Best-effort read-ahead requests for spans of the mailbox mapping.

use std::ops::Range;

use memmap2::Mmap;

#[cfg(unix)]
pub(crate) fn read_ahead(map: &Mmap, span: Range<usize>) {
    map.advise_range(memmap2::Advice::WillNeed, span.start, span.len())
        .unwrap_or_default();
}

#[cfg(not(unix))]
pub(crate) const fn read_ahead(_map: &Mmap, _span: Range<usize>) {}
