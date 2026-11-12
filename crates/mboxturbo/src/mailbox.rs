//! An mbox file mapped read-only together with its message index.

use std::fs::File;
use std::io;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

use memmap2::Mmap;
use rayon::prelude::*;

use crate::builder::{BlockSize, IndexPolicy, IndexSource, MailboxBuilder};
use crate::error::MboxTurboError;
use crate::fingerprint::Fingerprint;
use crate::hint;
use crate::index::{Cursor, Index};
use crate::message::Message;

/// An mbox file mapped read-only, with the byte offset of every message.
///
/// The file must not be modified or truncated while the mailbox, or any [`Message`] taken
/// from it, is alive. The same holds for an index file passed to [`Mailbox::open_cached`], which
/// this crate only ever replaces by renaming a new file over it.
#[derive(Debug)]
pub struct Mailbox {
    /// The read-only mapping, shared with every [`Message`] taken from this mailbox.
    contents: Arc<Mmap>,
    /// Start offsets of the messages within `contents`.
    index: Index,
    /// Where `index` came from, as reported by [`Mailbox::index_source`].
    source: IndexSource,
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
pub(crate) struct Mapped {
    /// The read-only mapping of the whole file, shared with the index for a rebuild.
    contents: Arc<Mmap>,
    /// Identity of the mapped bytes, which a cached index must match to be reused.
    fingerprint: Fingerprint,
}

impl Mapped {
    /// Builds a fresh index over the mapping, with blocks of `block_size` messages when given.
    pub(crate) fn build(&self, block_size: Option<BlockSize>) -> Index {
        let contents = Arc::clone(&self.contents);
        match block_size {
            Some(size) => Index::build_with(contents, self.fingerprint, size.shift()),
            None => Index::build(contents, self.fingerprint),
        }
    }

    /// Loads the index saved at `index_path`, which must match this mapping's fingerprint.
    pub(crate) fn load(&self, index_path: &Path) -> Result<Index, MboxTurboError> {
        Index::load(index_path, Arc::clone(&self.contents), self.fingerprint)
    }

    /// Opens and maps `path`, fingerprinting what was mapped.
    ///
    /// Fails with [`MboxTurboError::Io`] when the file cannot be opened or mapped.
    pub(crate) fn open(path: &Path) -> Result<Self, MboxTurboError> {
        let file = File::open(path).map_err(|source| MboxTurboError::io(path, source))?;
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
        let contents =
            Arc::new(map_read_only(&file).map_err(|source| MboxTurboError::io(path, source))?);
        let fingerprint = Fingerprint::new(&contents, modified);
        Ok(Self {
            contents,
            fingerprint,
        })
    }

    /// Attaches an index that was already validated against this mapping's fingerprint.
    pub(crate) fn with_index(self, index: Index, source: IndexSource) -> Mailbox {
        Mailbox {
            contents: self.contents,
            index,
            source,
        }
    }
}

impl Mailbox {
    /// The bytes of `span`, or an empty span and slice when the index has no span inside the
    /// file contents.
    fn bounded(&self, span: Option<Range<usize>>) -> (Range<usize>, &[u8]) {
        span.and_then(|inside| Some((inside.clone(), self.contents.get(inside)?)))
            .unwrap_or((0..0, &[]))
    }

    /// Narrows `positions` to the messages that exist. A range that starts past the end becomes
    /// empty and sits at the end, never inverted.
    pub(crate) fn clamped(&self, positions: Range<usize>) -> Range<usize> {
        let end = positions.end.min(self.len());
        positions.start.min(end)..end
    }

    /// [`Mailbox::row`] with the span answered by `cursor`, which must walk this mailbox's index.
    fn cursor_row(&self, cursor: &mut Cursor<'_>, position: usize) -> (Range<usize>, &[u8]) {
        self.bounded(cursor.span(position))
    }

    /// Unix seconds of the Date header of the message at `position`, as the index recorded it,
    /// or `None` when the message has no parsable Date or `position` is past the last message.
    /// A Date of exactly the epoch reads as missing, because the index stores 0 for a message
    /// with no Date header.
    #[must_use]
    pub fn date(&self, position: usize) -> Option<i64> {
        self.index.date(position).filter(|&seconds| seconds != 0)
    }

    /// The message index.
    #[must_use]
    pub const fn index(&self) -> &Index {
        &self.index
    }

    /// Where the index being served came from: the file it was read from or written to, or
    /// memory. A file is reported only while it matches what is served: after a lookup rebuilt
    /// the index and rewriting the file failed, the file no longer matches what is served
    /// and this reports [`IndexSource::Memory`].
    #[must_use]
    pub fn index_source(&self) -> IndexSource {
        match &self.source {
            IndexSource::File(path) if !matches!(self.index.rewrite_outcome(), Some(Err(_))) => {
                IndexSource::File(path.clone())
            },
            IndexSource::File(_) | IndexSource::Memory => IndexSource::Memory,
        }
    }

    /// Whether the mailbox holds no messages.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Raw bytes of every message, in file order.
    #[must_use]
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &[u8]> + DoubleEndedIterator {
        let mut cursor = self.index.cursor();
        (0..self.len()).map(move |position| self.cursor_row(&mut cursor, position).1)
    }

    /// Number of messages.
    #[must_use]
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// The message at `position`, parsed lazily on first field access.
    #[must_use]
    pub fn message(&self, position: usize) -> Option<Message> {
        Some(Message::new(
            Arc::clone(&self.contents),
            self.index.span(position)?,
        ))
    }

    /// Maps the mbox at `path` and serves its index from the sidecar file `<path>.mbxidx`
    /// beside it, so a later open of the same mbox skips the scan. A missing, stale or damaged
    /// sidecar is rebuilt on all rayon threads and written back. When it cannot be written, for
    /// example in a read-only directory, the open still succeeds with an index held in memory
    /// and leaves nothing behind; [`Mailbox::index_source`] tells which happened.
    ///
    /// # Errors
    ///
    /// [`MboxTurboError::Io`] when the mbox cannot be opened or mapped.
    pub fn open<P>(path: P) -> Result<Self, MboxTurboError>
    where
        P: AsRef<Path>,
    {
        MailboxBuilder::new().open(path)
    }

    /// Maps the mbox at `path`, reusing the index saved at `index_path` when it still matches
    /// the mailbox. When it is missing or stale, a new index is built and saved there.
    ///
    /// # Errors
    ///
    /// [`MboxTurboError::Io`] when either file cannot be read or the new index cannot be written,
    /// and [`MboxTurboError::CorruptIndex`] when the header of `index_path` is damaged; that file
    /// is left in place for inspection rather than overwritten. Only the header is checked here:
    /// a damaged block is found by the first lookup that reaches it, which rescans the mailbox
    /// and rewrites `index_path` with the repaired index when its directory is writable.
    pub fn open_cached<P, Q>(path: P, index_path: Q) -> Result<Self, MboxTurboError>
    where
        P: AsRef<Path>,
        Q: AsRef<Path>,
    {
        MailboxBuilder::new()
            .index(IndexPolicy::Path(index_path.as_ref().to_path_buf()))
            .open(path)
    }

    /// Raw bytes of every message, split across rayon threads.
    #[must_use]
    pub fn par_iter(&self) -> impl IndexedParallelIterator<Item = &[u8]> {
        (0..self.len()).into_par_iter().map_init(
            || self.index.cursor(),
            |cursor, position| self.cursor_row(cursor, position).1,
        )
    }

    /// The messages at `positions` (clamped to those that exist), all parsed in parallel.
    ///
    /// `messages` holds every message in the clamped range in position order, including those
    /// that failed to parse; `unparsed` lists the positions among them whose full parse
    /// produced nothing.
    #[must_use]
    pub fn parse_batch(&self, positions: Range<usize>) -> ParsedBatch {
        let parsed: Vec<(usize, bool, Message)> = self
            .clamped(positions)
            .into_par_iter()
            .map(|position| {
                let (span, _raw) = self.row(position);
                let message = Message::new(Arc::clone(&self.contents), span);
                (position, message.parse(), message)
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

    /// Raw bytes of the message at `position`, including its `From ` separator line.
    #[must_use]
    pub fn raw(&self, position: usize) -> Option<&[u8]> {
        self.contents.get(self.index.span(position)?)
    }

    /// The span and raw bytes of the message at `position`, which must be below `len()`.
    ///
    /// The index answers every position below its count with a span inside the mapping, except
    /// one that a forged index file claimed and the rescan it triggered then disowned: a header
    /// with a valid checksum and this mailbox's fingerprint can claim more messages than the
    /// mailbox holds. Such a position yields an empty span at 0 and an empty slice, so iterators
    /// sized from the claimed count still end without a panic.
    fn row(&self, position: usize) -> (Range<usize>, &[u8]) {
        self.bounded(self.index.span(position))
    }

    /// The span and raw bytes of every message in `positions`, clamped to the messages that
    /// exist, as `(position, span, raw)`.
    ///
    /// Yields one item for every clamped position and never skips one. The index answers every
    /// position below its count with a span inside the mapping, apart from a position a forged
    /// index claimed and its rescan disowned, which yields an empty span and slice. A built index
    /// takes its starts from the scanner, which emits them ascending and each below the
    /// mapping's length. A cached index is accepted only when its fingerprint, which includes
    /// the length, matches the mapping's; each of its blocks is checked on first use, and a
    /// block that fails its checksum or places a message outside the mapping makes
    /// the index answer from a rescan instead.
    pub(crate) fn rows(
        &self,
        positions: Range<usize>,
    ) -> impl Iterator<Item = (usize, Range<usize>, &[u8])> {
        let mut cursor = self.index.cursor();
        self.clamped(positions).map(move |position| {
            let (span, raw) = self.cursor_row(&mut cursor, position);
            (position, span, raw)
        })
    }
}

#[expect(
    unsafe_code,
    reason = "a read-only map is sound while the file is neither written nor truncated, which \
              is the documented contract of Mailbox and of every Message borrowed from it"
)]
/// Maps `file` read-only; the caller upholds the no-write, no-truncate contract of [`Mailbox`],
/// which covers both the mbox and a cached index file.
pub(crate) fn map_read_only(file: &File) -> io::Result<Mmap> {
    // SAFETY: a read-only map is sound while the file is neither written nor truncated, which
    // is the documented contract of `Mailbox` and of every `Message` borrowed from it.
    unsafe { Mmap::map(file) }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write as _;

    use tempfile::{NamedTempFile, TempDir};
    use xxhash_rust::xxh3::xxh3_64;

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
    fn positions_past_the_end_are_clamped_to_the_messages_that_exist() {
        let (_file, mailbox) = three_message_mailbox();
        assert_eq!(mailbox.clamped(1..99), 1..3, "end is cut to the length");
    }

    #[test]
    fn a_range_starting_past_the_end_becomes_empty_at_the_end() {
        let (_file, mailbox) = three_message_mailbox();
        assert_eq!(mailbox.clamped(9..12), 3..3, "start must not exceed end");
    }

    #[test]
    fn positions_inside_the_mailbox_are_unchanged() {
        let (_file, mailbox) = three_message_mailbox();
        assert_eq!(mailbox.clamped(1..2), 1..2, "in-range input is kept");
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

    #[test]
    fn a_position_a_forged_index_claims_yields_an_empty_message() {
        let dir = TempDir::new().expect("a temporary directory is created");
        let mbox = dir.path().join("mbox");
        let cache = dir.path().join("mbox.idx");
        fs::write(&mbox, MBOX).expect("fixture mbox is written");
        drop(Mailbox::open_cached(&mbox, &cache).expect("the first open builds the cache"));
        let mut bytes = fs::read(&cache).expect("the saved index reads back");
        let count: [u8; 8] = bytes[48..56]
            .try_into()
            .expect("the count field is eight bytes");
        bytes[48..56].copy_from_slice(&(u64::from_le_bytes(count) + 1).to_le_bytes());
        let checksum = xxh3_64(&bytes[..64]);
        bytes[64..72].copy_from_slice(&checksum.to_le_bytes());
        fs::write(&cache, bytes).expect("the forged index is written");
        let mailbox = Mailbox::open_cached(&mbox, &cache).expect("the forged header is accepted");
        let raws: Vec<&[u8]> = mailbox.iter().collect();
        assert_eq!(
            raws.len(),
            4,
            "iteration covers the claimed count without a panic"
        );
        assert!(
            raws[3].is_empty(),
            "the phantom position yields an empty message"
        );
        assert_eq!(mailbox.len(), 3, "the rebuilt index reports the true count");
    }

    #[test]
    fn the_indexed_date_equals_the_parsed_date_and_is_none_when_missing() {
        const DATED: &[u8] =
            b"From a@x Mon Jan  1 00:00:00 2024\nDate: Mon, 1 Jan 2024 10:00:00 +0100\n\
Subject: one\n\nfirst\n\
From b@x Mon Jan  1 00:00:01 2024\nDate: Mon, 1 Jan 2024 10:00:00 -0500\n\
Subject: two\n\nsecond\n\
From c@x Mon Jan  1 00:00:02 2024\nSubject: three\n\nthird\n";
        let mut file = NamedTempFile::new().expect("temp file is created");
        file.write_all(DATED).expect("fixture mbox is written");
        let mailbox = Mailbox::open(file.path()).expect("fixture mbox opens");
        for position in 0..mailbox.len() {
            let parsed = mailbox
                .message(position)
                .and_then(|message| message.date())
                .map(|date| date.unix_seconds);
            assert_eq!(
                mailbox.date(position),
                parsed,
                "the indexed date is the parsed Date at position {position}"
            );
        }
        assert_eq!(
            mailbox.date(2),
            None,
            "a message without a Date header has no indexed date"
        );
        assert_eq!(
            mailbox.date(mailbox.len()),
            None,
            "a position past the last message has no indexed date"
        );
    }
}
