//! An mbox file mapped read-only together with its message index.

use std::array;
use std::fs::File;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

use memmap2::Mmap;
use rayon::prelude::*;

use crate::builder::{IndexOrigin, IndexPolicy, IndexSource, MailboxBuilder};
use crate::error::MboxTurboError;
use crate::fingerprint::Fingerprint;
use crate::hint;
use crate::index::{BlockSize, Cursor, Index};
use crate::mapping::map_read_only;
use crate::message::Message;
use crate::selection::Selection;

/// The line that opens every message.
const SEPARATOR: &[u8; 5] = b"From ";

/// The line feed that ends a message followed by the separator of the next one: the six bytes
/// around every message start but the first.
const SEPARATOR_AFTER_LINE: &[u8; 6] = b"\nFrom ";

/// A span no boundary of a mapping can fall on, for a check with no boundary already checked:
/// every offset of a mapping is below `isize::MAX`.
const NONE_CHECKED: Range<usize> = usize::MAX..usize::MAX;

/// Rows a walk reads ahead once it asks for consecutive positions. Their spans are taken from
/// the index first and their boundaries checked together after, so the reads of mailbox bytes
/// those checks make overlap instead of each waiting behind the index lookup of its row.
const AHEAD: usize = 16;

/// An index cursor for a walk over rows, with the span of the row it handed out last and the
/// checked spans of the rows it read ahead.
///
/// Both ends of every span it holds were checked against the mapped bytes, or answered by a
/// rebuild, so the next row, forwards or backwards, checks only the boundary it does not share
/// with the last one.
#[derive(Debug)]
struct Walk<'index> {
    /// The spans of the positions from `first`, of which the leading `ready` are checked.
    ahead: [Range<usize>; AHEAD],
    /// The span of the last row handed out, or [`NONE_CHECKED`] before the first.
    checked: Range<usize>,
    /// The cursor answering each row's span from this mailbox's index.
    cursor: Cursor<'index>,
    /// The position after the last row the walk may be asked for; nothing is read from it on.
    end: usize,
    /// The position of the first span in `ahead`.
    first: usize,
    /// The position after the last row handed out, so that asking for it reads ahead;
    /// `usize::MAX`, which no row has, before the first row.
    next: usize,
    /// How many spans of `ahead` were read and checked.
    ready: usize,
}

impl<'index> Walk<'index> {
    /// The checked span read ahead for `position`, if one was.
    #[inline]
    fn ahead(&self, position: usize) -> Option<Range<usize>> {
        // A position before `first` wraps past every count of `ready`.
        let offset = position.wrapping_sub(self.first);
        if offset < self.ready {
            self.ahead.get(offset).cloned()
        } else {
            None
        }
    }

    /// A walk over positions below `end` with no row handed out yet.
    fn new(cursor: Cursor<'index>, end: usize) -> Self {
        Self {
            ahead: array::from_fn(|_| NONE_CHECKED),
            checked: NONE_CHECKED,
            cursor,
            end,
            first: 0,
            next: usize::MAX,
            ready: 0,
        }
    }

    /// Fills `ahead` from the cursor with the spans from `position`, up to [`AHEAD`] of them and
    /// none at `end` or past it, and returns how many were read. Reading stops at the first span
    /// the index cannot answer or that ends past `length`, the mapping's, which the caller
    /// answers on its own.
    fn read(&mut self, position: usize, length: usize) -> usize {
        self.ready = 0;
        self.first = position;
        let mut read = 0_usize;
        for (slot, ahead) in self.ahead.iter_mut().zip(position..self.end) {
            match self.cursor.span(ahead) {
                Some(span) if span.end <= length => *slot = span,
                Some(_) | None => break,
            }
            read = read.saturating_add(1);
        }
        read
    }
}

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
    /// Whether opening loaded `index` or built it, as reported by [`Mailbox::index_origin`].
    origin: IndexOrigin,
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

/// The result of [`Mailbox::date_range`]: the selected positions and the undated count.
///
/// Converts into [`Selection::Positions`](crate::Selection::Positions) with `Selection::from`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DateRange {
    /// Positions, ascending, of the messages inside the requested range.
    pub positions: Vec<usize>,
    /// Messages with no index date. They are excluded from `positions` whenever a bound was given.
    pub undated: usize,
}

impl From<DateRange> for Selection {
    fn from(range: DateRange) -> Self {
        Self::Positions(range.positions)
    }
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
    /// Builds a fresh index over the mapping, with blocks of `block_size` messages.
    pub(crate) fn build(&self, block_size: BlockSize) -> Index {
        Index::build_with(Arc::clone(&self.contents), self.fingerprint, block_size)
    }

    /// Loads the index saved at `index_path`, which must match this mapping's fingerprint.
    pub(crate) fn load(&self, index_path: &Path) -> Result<Index, MboxTurboError> {
        Index::load(index_path, Arc::clone(&self.contents), self.fingerprint)
    }

    /// Loads the sidecar index of the mbox at `mbox` saved at `sidecar`, which must match this
    /// mapping's fingerprint, and refuses it, mapping nothing, unless it is a regular file owned
    /// by the mbox's owner. See [`Index::load_trusted`].
    pub(crate) fn load_sidecar(
        &self,
        sidecar: &Path,
        mbox: &Path,
    ) -> Result<Index, MboxTurboError> {
        Index::load_trusted(sidecar, mbox, Arc::clone(&self.contents), self.fingerprint)
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
    pub(crate) fn with_index(
        self,
        index: Index,
        source: IndexSource,
        origin: IndexOrigin,
    ) -> Mailbox {
        Mailbox {
            contents: self.contents,
            index,
            source,
            origin,
        }
    }
}

impl Mailbox {
    /// `span` as a span whose ends were checked: itself when it lies inside the mapping, which
    /// [`Mailbox::on_boundaries`] reads, else [`NONE_CHECKED`], since a span past the end
    /// passes that check unread.
    #[inline]
    fn as_checked(&self, span: &Range<usize>) -> Range<usize> {
        if span.end <= self.contents.len() {
            span.clone()
        } else {
            NONE_CHECKED
        }
    }

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

    /// `span`, the index's answer for `position`, when it still sits on message boundaries of
    /// the mapped bytes; an end of `checked` counts as one without being read again. Otherwise
    /// the file was rewritten under an index that its fingerprint still accepted, so the index
    /// is rebuilt and answers again from the rescan.
    #[inline]
    fn confirmed(
        &self,
        position: usize,
        span: Option<Range<usize>>,
        checked: &Range<usize>,
    ) -> Option<Range<usize>> {
        let inside = span?;
        if self.on_boundaries(&inside, checked) || self.index.is_rebuilt() {
            return Some(inside);
        }
        self.index.force_rebuild();
        self.index.span(position)
    }

    /// Unix seconds of the Date header of the message at `position`, as the index recorded it,
    /// or `None` when the message has no parsable Date or `position` is past the last message.
    #[must_use]
    pub fn date(&self, position: usize) -> Option<i64> {
        self.index.date(position)
    }

    /// The positions of the messages whose index date `d` satisfies `since <= d < until`, in
    /// ascending order, and the number of messages with no index date.
    ///
    /// Bounds are unix seconds, inclusive for `since` and exclusive for `until`; `None` leaves
    /// that side open. Both bounds with `since >= until` select nothing. A message without an
    /// index date (no Date header, or one that did not parse) matches no bound, so it is
    /// excluded whenever either bound is given; with neither, every position is returned.
    /// [`DateRange::undated`] counts those messages in every case. Only the index is read,
    /// never the message bytes.
    #[must_use]
    pub fn date_range(&self, since: Option<i64>, until: Option<i64>) -> DateRange {
        self.dates_among(0..self.len(), since, until)
    }

    /// [`Mailbox::date_range`] over `candidates`, which must all be below the mailbox length:
    /// the candidates inside the bounds, in the order given, and how many of them are undated.
    pub(crate) fn dates_among(
        &self,
        candidates: impl IntoIterator<Item = usize>,
        since: Option<i64>,
        until: Option<i64>,
    ) -> DateRange {
        let unbounded = since.is_none() && until.is_none();
        let mut range = DateRange {
            positions: Vec::new(),
            undated: 0,
        };
        for position in candidates {
            let kept = self.date(position).map_or_else(
                || {
                    range.undated = range.undated.saturating_add(1);
                    unbounded
                },
                |date| {
                    since.is_none_or(|bound| bound <= date)
                        && until.is_none_or(|bound| date < bound)
                },
            );
            if kept {
                range.positions.push(position);
            }
        }
        range
    }

    /// The message index.
    #[must_use]
    pub const fn index(&self) -> &Index {
        &self.index
    }

    /// Whether opening this mailbox loaded its index from a file or rebuilt it. A block rebuilt
    /// later by a lookup does not change the answer.
    #[must_use]
    pub const fn index_origin(&self) -> IndexOrigin {
        self.origin
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

    /// Whether `offset` is where a message starts: the first byte or the one after a line feed,
    /// with a `From ` separator there.
    #[inline]
    fn is_start(&self, offset: usize) -> bool {
        offset.checked_sub(1).map_or_else(
            || self.contents.starts_with(SEPARATOR),
            |before| {
                self.contents
                    .get(before..)
                    .is_some_and(|line| line.starts_with(SEPARATOR_AFTER_LINE))
            },
        )
    }

    /// Raw bytes of every message, in file order.
    #[must_use]
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &[u8]> + DoubleEndedIterator {
        let mut walk = Walk::new(self.index.cursor(), self.len());
        (0..self.len()).map(move |position| self.walk_row(&mut walk, position).1)
    }

    /// Number of messages.
    #[must_use]
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// The message at `position`, parsed lazily on first field access.
    #[must_use]
    pub fn message(&self, position: usize) -> Option<Message> {
        let span = self.confirmed(position, self.index.span(position), &NONE_CHECKED)?;
        Some(Message::new(Arc::clone(&self.contents), span))
    }

    /// Whether `span` starts at a message start and ends at one or at the end of the mapping.
    /// An offset that is an end of `checked`, a span whose ends were both checked already, is
    /// taken as a boundary without reading it. A span outside the mapping passes, because
    /// [`Mailbox::bounded`] already turns it into an empty message.
    #[inline]
    fn on_boundaries(&self, span: &Range<usize>, checked: &Range<usize>) -> bool {
        let length = self.contents.len();
        if span.end > length {
            return true;
        }
        let known = |offset: usize| offset == checked.start || offset == checked.end;
        (known(span.start) || self.is_start(span.start))
            && (span.end == length || known(span.end) || self.is_start(span.end))
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
            || Walk::new(self.index.cursor(), self.len()),
            |walk, position| self.walk_row(walk, position).1,
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
        self.contents
            .get(self.confirmed(position, self.index.span(position), &NONE_CHECKED)?)
    }

    /// The span of `position` after reading up to [`AHEAD`] rows from it into `walk` and
    /// checking all their boundaries. When one fails, the index is rebuilt, nothing read ahead
    /// is kept, and the rebuild answers. A row that cannot be read ahead, because the index has
    /// no span for it or its span ends past the mapping, is answered as a lone row is.
    fn read_ahead(&self, walk: &mut Walk<'_>, position: usize) -> Option<Range<usize>> {
        let read = walk.read(position, self.contents.len());
        if read == 0 {
            return self.confirmed(position, walk.cursor.span(position), &walk.checked);
        }
        let mut previous = walk.checked.clone();
        let mut sound = true;
        for span in walk.ahead.iter().take(read) {
            sound &= self.on_boundaries(span, &previous);
            previous = span.clone();
        }
        if sound || self.index.is_rebuilt() {
            walk.ready = read;
            return walk.ahead(position);
        }
        self.index.force_rebuild();
        self.index.span(position)
    }

    /// The span and raw bytes of the message at `position`, which must be below `len()`.
    ///
    /// The index answers every position below its count with a span inside the mapping, except
    /// one that a forged index file claimed and the rescan it triggered then disowned: a header
    /// with a valid checksum and this mailbox's fingerprint can claim more messages than the
    /// mailbox holds. Such a position yields an empty span at 0 and an empty slice, so iterators
    /// sized from the claimed count still end without a panic.
    fn row(&self, position: usize) -> (Range<usize>, &[u8]) {
        self.bounded(self.confirmed(position, self.index.span(position), &NONE_CHECKED))
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
        let clamped = self.clamped(positions);
        let mut walk = Walk::new(self.index.cursor(), clamped.end);
        clamped.map(move |position| {
            let (span, raw) = self.walk_row(&mut walk, position);
            (position, span, raw)
        })
    }

    /// [`Mailbox::row`] with the span answered by `walk`'s cursor, which must walk this
    /// mailbox's index, checking only the boundary the row does not share with `walk`'s last.
    #[inline]
    fn walk_row(&self, walk: &mut Walk<'_>, position: usize) -> (Range<usize>, &[u8]) {
        let span = match walk.ahead(position) {
            Some(inside) => Some(inside),
            None if position == walk.next => self.read_ahead(walk, position),
            None => self.confirmed(position, walk.cursor.span(position), &walk.checked),
        };
        walk.next = position.saturating_add(1);
        walk.checked = span
            .as_ref()
            .map_or(NONE_CHECKED, |inside| self.as_checked(inside));
        self.bounded(span)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write as _;

    use tempfile::{NamedTempFile, TempDir};
    use xxhash_rust::xxh3::xxh3_64;

    use super::Mailbox;
    use crate::index::BlockSize;

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

    #[test]
    fn one_iter_pass_decodes_each_block_once() {
        let messages = 600_usize;
        let mut file = NamedTempFile::new().expect("temp file is created");
        for number in 0..messages {
            write!(
                file,
                "From a@x Mon Jan  1 00:00:00 2024\nSubject: {number}\n\nbody\n"
            )
            .expect("fixture message is written");
        }
        let mailbox = Mailbox::open(file.path()).expect("fixture mbox opens");
        assert_eq!(mailbox.iter().count(), messages, "one item per message");
        assert_eq!(
            mailbox.index().decoded_blocks(),
            messages.div_ceil(BlockSize::default().entries()),
            "a cursor pass decodes each block's starts once, not once per message"
        );
    }
}
