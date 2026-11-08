//! An mbox file mapped read-only together with its message index.

use std::fs::File;
use std::io;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

use memmap2::Mmap;
use rayon::prelude::*;

use crate::error::MboxturboError;
use crate::fingerprint::Fingerprint;
use crate::hint;
use crate::index::Index;
use crate::message::Message;

/// An mbox file mapped read-only, with the byte offset of every message.
///
/// The file must not be modified or truncated while the mailbox, or any [`Message`] taken
/// from it, is alive.
#[derive(Debug)]
pub struct Mailbox {
    /// The read-only mapping, shared with every [`Message`] taken from this mailbox.
    contents: Arc<Mmap>,
    /// Start offsets of the messages within `contents`.
    index: Index,
}

/// The result of [`Mailbox::parse_batch`]: the parsed messages and the positions that failed.
#[derive(Debug)]
#[non_exhaustive]
pub struct ParsedBatch {
    /// Every existing message in the requested range, in position order, failed parses included.
    pub messages: Vec<Message>,
    /// Mailbox positions, ascending, whose full parse produced nothing. This includes a message
    /// whose parser panicked, which is contained and reported the same way as a message with no
    /// MIME part.
    pub unparsed: Vec<usize>,
}

/// A mapped file with its fingerprint, before an index is attached.
#[derive(Debug)]
struct Mapped {
    /// The read-only mapping of the whole file.
    contents: Mmap,
    /// Identity of the mapped bytes, which a cached index must match to be reused.
    fingerprint: Fingerprint,
}

impl Mapped {
    /// Opens and maps `path`, fingerprinting what was mapped.
    ///
    /// Fails with [`MboxturboError::Io`] when the file cannot be opened or mapped.
    fn open(path: &Path) -> Result<Self, MboxturboError> {
        let file = File::open(path).map_err(|source| MboxturboError::io(path, source))?;
        #[expect(
            clippy::disallowed_methods,
            reason = "a missing modification time becomes mtime 0: the length and sample hash in \
                      the fingerprint still guard a cached index, and a platform or filesystem \
                      without mtime support must still open"
        )]
        let modified = file
            .metadata()
            .and_then(|metadata| metadata.modified())
            .ok();
        let contents = map_read_only(&file).map_err(|source| MboxturboError::io(path, source))?;
        let fingerprint = Fingerprint::new(&contents, modified);
        Ok(Self {
            contents,
            fingerprint,
        })
    }

    /// Builds a fresh index over the mapping.
    fn into_indexed(self) -> Mailbox {
        let index = Index::build(&self.contents, self.fingerprint);
        Mailbox {
            contents: Arc::new(self.contents),
            index,
        }
    }

    /// Attaches an index that was already validated against this mapping's fingerprint.
    fn with_index(self, index: Index) -> Mailbox {
        Mailbox {
            contents: Arc::new(self.contents),
            index,
        }
    }
}

#[expect(
    unsafe_code,
    reason = "a read-only map is sound while the file is neither written nor truncated, which \
              is the documented contract of Mailbox and of every Message borrowed from it"
)]
#[expect(
    clippy::undocumented_unsafe_blocks,
    reason = "the safety argument is the reason on the unsafe_code expectation; the crate keeps \
              code free of comments"
)]
/// Maps `file` read-only; the caller upholds the no-write, no-truncate contract of [`Mailbox`].
fn map_read_only(file: &File) -> io::Result<Mmap> {
    unsafe { Mmap::map(file) }
}

impl Mailbox {
    /// Maps the mbox at `path` and indexes it on all rayon threads.
    ///
    /// # Errors
    ///
    /// [`MboxturboError::Io`] when the file cannot be opened or mapped.
    pub fn open<P>(path: P) -> Result<Self, MboxturboError>
    where
        P: AsRef<Path>,
    {
        Ok(Mapped::open(path.as_ref())?.into_indexed())
    }

    /// Maps the mbox at `path`, reusing the index saved at `index_path` when it still matches
    /// the mailbox. When it is missing or stale, a new index is built and saved there.
    ///
    /// # Errors
    ///
    /// [`MboxturboError::Io`] when either file cannot be read or the new index cannot be written,
    /// and [`MboxturboError::CorruptIndex`] when `index_path` exists but fails validation; a
    /// corrupt file is left in place for inspection rather than overwritten.
    pub fn open_cached<P, Q>(path: P, index_path: Q) -> Result<Self, MboxturboError>
    where
        P: AsRef<Path>,
        Q: AsRef<Path>,
    {
        let cache_file = index_path.as_ref();
        let mapped = Mapped::open(path.as_ref())?;
        match Index::load(cache_file, mapped.fingerprint) {
            Ok(index) => Ok(mapped.with_index(index)),
            Err(error) if error.calls_for_rebuild() => {
                let mailbox = mapped.into_indexed();
                mailbox.index.save(cache_file)?;
                Ok(mailbox)
            },
            Err(error) => Err(error),
        }
    }

    /// The message index.
    #[must_use]
    pub const fn index(&self) -> &Index {
        &self.index
    }

    /// Number of messages.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.index.len()
    }

    /// Whether the mailbox holds no messages.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Raw bytes of the message at `position`, including its `From ` separator line.
    #[must_use]
    pub fn raw(&self, position: usize) -> Option<&[u8]> {
        self.contents.get(self.index.span(position)?)
    }

    /// The span and raw bytes of every message in `positions`, clamped to the messages that
    /// exist, as `(position, span, raw)`.
    ///
    /// Yields one item for every clamped position and never skips one. This rests on one
    /// invariant: every index in use has starts that ascend, each below its end. A freshly
    /// built index takes `end` from `contents.len()` in `Index::build`, and its starts come
    /// from the scanner, which emits them ascending and each below that length. A cached index
    /// is accepted by `Index::decode` only when its fingerprint, which includes the length,
    /// matches the mapping's, and `validate_starts` has checked that its starts ascend with the
    /// last one below `end`.
    pub(crate) fn rows(
        &self,
        positions: Range<usize>,
    ) -> impl Iterator<Item = (usize, Range<usize>, &[u8])> {
        let end = positions.end.min(self.len());
        let start = positions.start.min(end);
        (start..end).map(|position| {
            let (span, raw) = self.row(position);
            (position, span, raw)
        })
    }

    /// The span and raw bytes of the message at `position`, which must be below `len()`.
    #[expect(
        clippy::expect_used,
        reason = "`position` is below `len()`, so the index has a span for it, and every index in \
                  use keeps its spans inside the mapping: `Index::build` takes `end` from \
                  `contents.len()` and emits ascending starts below it, and `Index::decode` \
                  accepts a cached index only on a matching fingerprint and after \
                  `validate_starts` checked its starts"
    )]
    fn row(&self, position: usize) -> (Range<usize>, &[u8]) {
        let span = self
            .index
            .span(position)
            .expect("a position below len() has a span");
        let raw = self
            .contents
            .get(span.clone())
            .expect("a validated index spans bytes inside the mapping");
        (span, raw)
    }

    /// Raw bytes of every message, in file order.
    #[must_use]
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &[u8]> + DoubleEndedIterator {
        (0..self.len()).map(|position| self.row(position).1)
    }

    /// Raw bytes of every message, split across rayon threads.
    #[must_use]
    pub fn par_iter(&self) -> impl IndexedParallelIterator<Item = &[u8]> {
        (0..self.len())
            .into_par_iter()
            .map(|position| self.row(position).1)
    }

    /// The message at `position`, parsed lazily on first field access.
    #[must_use]
    pub fn message(&self, position: usize) -> Option<Message> {
        Some(Message::new(
            Arc::clone(&self.contents),
            self.index.span(position)?,
        ))
    }

    /// The messages at `positions` (clamped to those that exist), all parsed in parallel.
    ///
    /// `messages` holds every message in the clamped range in position order, including those
    /// that failed to parse; `unparsed` lists the positions among them whose full parse
    /// produced nothing.
    #[must_use]
    pub fn parse_batch(&self, positions: Range<usize>) -> ParsedBatch {
        let end = positions.end.min(self.len());
        let parsed: Vec<(usize, bool, Message)> = (positions.start.min(end)..end)
            .into_par_iter()
            .filter_map(|position| {
                let message = self.message(position)?;
                Some((position, message.parse(), message))
            })
            .collect();
        let mut batch = ParsedBatch {
            messages: Vec::with_capacity(parsed.len()),
            unparsed: Vec::new(),
        };
        for (position, complete, message) in parsed {
            if !complete {
                batch.unparsed.push(position);
            }
            batch.messages.push(message);
        }
        batch
    }

    /// Asks the kernel to start reading the messages at `positions` in the background.
    pub fn prefetch(&self, positions: Range<usize>) {
        if let Some(span) = self.index.span_of(positions) {
            hint::read_ahead(&self.contents, span);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use tempfile::NamedTempFile;

    use super::Mailbox;

    const MBOX: &[u8] = b"From a@x Mon Jan  1 00:00:00 2024\nSubject: one\n\nfirst\n\
From b@x Mon Jan  1 00:00:01 2024\nSubject: two\n\nsecond\n\
From c@x Mon Jan  1 00:00:02 2024\nSubject: three\n\nthird\n";

    fn three_message_mailbox() -> (NamedTempFile, Mailbox) {
        let mut file = NamedTempFile::new().expect("temp file is created");
        file.write_all(MBOX).expect("fixture mbox is written");
        let mailbox = Mailbox::open(file.path()).expect("fixture mbox opens");
        (file, mailbox)
    }

    #[test]
    fn rows_in_range_yield_one_row_per_position_with_its_span_and_bytes() {
        let (_file, mailbox) = three_message_mailbox();
        let rows: Vec<_> = mailbox.rows(0..3).collect();
        let positions: Vec<usize> = rows.iter().map(|(position, ..)| *position).collect();
        assert_eq!(positions, [0, 1, 2], "one row per position, in order");
        let spans: Vec<_> = rows.iter().map(|(_, span, _)| span.clone()).collect();
        let indexed: Vec<_> = (0..3)
            .filter_map(|position| mailbox.index().span(position))
            .collect();
        assert_eq!(
            spans, indexed,
            "each row span is the index span for its position"
        );
        let row_bytes: Vec<&[u8]> = rows.iter().map(|(_, _, raw)| *raw).collect();
        let file_bytes: Vec<&[u8]> = spans.iter().map(|span| &MBOX[span.clone()]).collect();
        assert_eq!(
            row_bytes, file_bytes,
            "each row holds the file bytes under its span"
        );
        assert_eq!(
            (spans[0].start, spans[2].end),
            (0, MBOX.len()),
            "the rows cover the file from its first byte to its last",
        );
    }

    #[test]
    fn rows_past_the_end_are_clamped_to_the_messages_that_exist() {
        let (_file, mailbox) = three_message_mailbox();
        let positions: Vec<usize> = mailbox
            .rows(1..10)
            .map(|(position, _span, _raw)| position)
            .collect();
        assert_eq!(positions, [1, 2], "only positions 1 and 2 exist in 1..10");
    }

    #[test]
    fn rows_starting_past_the_end_yield_nothing() {
        let (_file, mailbox) = three_message_mailbox();
        assert_eq!(
            mailbox.rows(5..9).count(),
            0,
            "a range wholly beyond the last message has no rows",
        );
    }
}
