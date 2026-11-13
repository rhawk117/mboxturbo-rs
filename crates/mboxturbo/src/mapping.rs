//! The one place a file is mapped read-only.
//!
//! [`map_read_only`] returns a read-only map of an open file. It is sound only while the file
//! is neither written nor truncated, so the caller must uphold the no-write, no-truncate
//! contract of [`Mailbox`](crate::Mailbox), which covers both the mbox and a cached index file.

use std::fs::File;
use std::io;

use memmap2::Mmap;

#[expect(
    unsafe_code,
    reason = "a read-only map is sound while the file is neither written nor truncated, which \
              is the documented contract of Mailbox and of every Message borrowed from it"
)]
/// Maps `file` read-only; the caller upholds the no-write, no-truncate contract of
/// [`Mailbox`](crate::Mailbox), which covers both the mbox and a cached index file.
pub(crate) fn map_read_only(file: &File) -> io::Result<Mmap> {
    // SAFETY: a read-only map is sound while the file is neither written nor truncated, which
    // is the documented contract of `Mailbox` and of every `Message` borrowed from it.
    unsafe { Mmap::map(file) }
}
