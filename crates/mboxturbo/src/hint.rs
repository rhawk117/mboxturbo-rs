//! Best-effort read-ahead requests for spans of the mailbox mapping.

use std::ops::Range;

use memmap2::Mmap;

/// Asks the kernel to read `span` of `map` into the page cache ahead of use.
///
/// Best-effort: a refused request is ignored and reads still work, only slower.
#[cfg(unix)]
#[expect(
    clippy::disallowed_methods,
    reason = "read-ahead is advisory, so a refused request only costs speed and the later reads \
              of the mapping are unaffected"
)]
pub(crate) fn read_ahead(map: &Mmap, span: Range<usize>) {
    map.advise_range(memmap2::Advice::WillNeed, span.start, span.len())
        .unwrap_or_default();
}

/// Does nothing: this platform has no read-ahead hint.
#[cfg(not(unix))]
pub(crate) const fn read_ahead(_map: &Mmap, _span: Range<usize>) {}

/// Tells the kernel the mapping `map` is about to be read front to back, so it reads ahead
/// aggressively and drops pages behind the reader.
///
/// Best-effort: a refused request is ignored and reads still work, only slower.
#[cfg(unix)]
#[expect(
    clippy::disallowed_methods,
    reason = "the advice is advisory, so a refused request only costs speed and the later reads \
              of the mapping are unaffected"
)]
pub(crate) fn sequential(map: &Mmap) {
    map.advise(memmap2::Advice::Sequential).unwrap_or_default();
}

/// Does nothing: this platform has no sequential-access hint.
#[cfg(not(unix))]
pub(crate) const fn sequential(_map: &Mmap) {}

/// Restores the default access pattern of `map` once a front-to-back pass is over.
///
/// Best-effort: a refused request is ignored and reads still work, only slower.
#[cfg(unix)]
#[expect(
    clippy::disallowed_methods,
    reason = "the advice is advisory, so a refused request only costs speed and the later reads \
              of the mapping are unaffected"
)]
pub(crate) fn normal(map: &Mmap) {
    map.advise(memmap2::Advice::Normal).unwrap_or_default();
}

/// Does nothing: this platform has no access-pattern hint.
#[cfg(not(unix))]
pub(crate) const fn normal(_map: &Mmap) {}
