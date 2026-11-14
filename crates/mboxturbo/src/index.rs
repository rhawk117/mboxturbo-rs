//! Message boundary index over the v2 block-directory file, verified one block at a time and
//! rebuilt from the mailbox when a block turns out to be damaged.

mod block;
mod build;
mod cache;
mod codec;
mod cursor;
mod date;
mod format;
mod trust;

use std::io::{self, Write as _};
use std::ops::Range;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::{fmt, iter};

use memmap2::Mmap;
use tempfile::NamedTempFile;

pub use self::block::BlockSize;
use self::build::encoded;
use self::cache::{Cell, Parsed};
pub(crate) use self::cursor::Cursor;
use self::format::{Layout, Section};
use crate::error::{Corruption, MboxTurboError};
use crate::fingerprint::Fingerprint;
use crate::scan::Parallelism;
use crate::width::{narrow, widen};

/// First eight bytes of every index file.
const MAGIC: [u8; 8] = *b"MBOXTIDX";

/// Where the bytes of an index file live.
#[derive(Debug)]
enum Backing {
    /// An index file mapped read-only; it is only ever replaced by a rename, never rewritten.
    Mapped(Mmap),
    /// An index encoded in memory by [`Index::build`].
    Owned(Vec<u8>),
}

/// Start offset and date of every message in one mailbox, tied to it by its [`Fingerprint`].
///
/// Opening a saved index reads only its header. Each block is checked against its checksum the
/// first time a lookup reaches it. A block that fails that check, or that places a message
/// outside the mailbox, makes the index rescan the mailbox once; every later lookup is answered
/// from that rebuild, and the file the index was loaded from is rewritten with it when its
/// directory allows. Lookups therefore never fail: they answer `None` only past the last message.
pub struct Index {
    /// One cell per dates block, filled with its parsed entry once the block passed its checksum.
    dates_entries: Box<[Cell]>,
    /// Starts blocks decoded by cursors, counted so tests can see each block read once.
    #[cfg(test)]
    decoded: AtomicUsize,
    /// Identity of the mailbox the index describes.
    fingerprint: Fingerprint,
    /// Header of `original`.
    layout: Layout,
    /// The mapped mailbox, rescanned when a block is damaged.
    mailbox: Arc<Mmap>,
    /// The file the index was loaded from, which a rebuild rewrites.
    origin: Option<PathBuf>,
    /// The index bytes as loaded or built, read until a rebuild replaces them.
    original: Backing,
    /// The bytes and header of the rebuild, once a damaged block forced one; never re-verified.
    replacement: OnceLock<(Vec<u8>, Layout)>,
    /// What rewriting `origin` with the rebuild produced, once a rebuild ran with an origin.
    rewrite: OnceLock<io::Result<()>>,
    /// One cell per starts block, filled with its parsed entry once the block passed its checksum.
    starts_entries: Box<[Cell]>,
}

/// Bytes of an index file by section, as reported by [`Index::bytes`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct IndexBytes {
    /// Payload bytes of every dates block.
    pub dates: u64,
    /// Bytes of the starts and dates directories together.
    pub directory: u64,
    /// Bytes of the file header.
    pub header: u64,
    /// Payload bytes of every starts block.
    pub starts: u64,
}

impl IndexBytes {
    /// The four sections added up, which is the length of the index file they describe.
    #[must_use]
    pub const fn total(self) -> u64 {
        self.dates
            .saturating_add(self.directory)
            .saturating_add(self.header)
            .saturating_add(self.starts)
    }
}

/// Why a stored index was not accepted; [`Rejection::at`] attaches the file path.
#[derive(Debug)]
enum Rejection {
    /// The bytes are not a valid index.
    Corrupt(Corruption),
    /// The index is well formed but built by an older format or for a different mailbox.
    Stale,
}

impl From<Corruption> for Rejection {
    fn from(corruption: Corruption) -> Self {
        Self::Corrupt(corruption)
    }
}

impl Rejection {
    /// The public error for this rejection of the index file at `path`.
    fn at(self, path: &Path) -> MboxTurboError {
        let index_path = path.to_path_buf();
        match self {
            Self::Corrupt(corruption) => MboxTurboError::CorruptIndex {
                path: index_path,
                corruption,
            },
            Self::Stale => MboxTurboError::StaleIndex { path: index_path },
        }
    }
}

impl Backing {
    /// The whole index file.
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Mapped(mapped) => mapped,
            Self::Owned(owned) => owned,
        }
    }
}

impl fmt::Debug for Index {
    #[expect(
        clippy::renamed_function_params,
        reason = "the trait calls it `f`, a one-letter name the min_ident_chars lint bans"
    )]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Index")
            .field("fingerprint", &self.fingerprint)
            .field("layout", self.active().1)
            .field("origin", &self.origin)
            .field("rebuilt", &self.replacement.get().is_some())
            .finish_non_exhaustive()
    }
}

impl PartialEq for Index {
    /// Two indexes are equal when they describe the same mailbox with the same bytes, whether
    /// mapped from a file, built in memory or rebuilt.
    fn eq(&self, other: &Self) -> bool {
        self.fingerprint == other.fingerprint && self.active().0 == other.active().0
    }
}

impl Eq for Index {}

/// The parsed entries of the blocks one lookup reads.
#[derive(Debug)]
enum Entries {
    /// The first and the last message needed lie in one block, so one entry serves both.
    One(Parsed),
    /// The first and the last message needed lie in different blocks.
    Two {
        /// The entry of the block holding the first message needed.
        first: Parsed,
        /// The entry of the block holding the last message needed that exists.
        last: Parsed,
    },
}

/// What one lookup reads: the index bytes and the parsed entries of the blocks holding the first
/// and the last message it needs.
#[derive(Debug)]
struct Reach<'lookup> {
    /// The index bytes the entries point into.
    bytes: &'lookup [u8],
    /// The entries of the blocks holding the first and the last message needed.
    entries: Entries,
    /// The header of `bytes`.
    layout: &'lookup Layout,
}

impl<'lookup> Reach<'lookup> {
    /// Date of the message at `position`, read from the first entry.
    #[expect(
        clippy::option_option,
        reason = "the outer `None` is a refused block, the inner one a message with no date"
    )]
    fn date(&self, position: usize) -> Option<Option<i64>> {
        self.first().frame().date(
            self.payload(self.first(), position)?,
            self.layout.place(position)?.1,
        )
    }

    /// The entry of the block holding the first message needed.
    const fn first(&self) -> &Parsed {
        match &self.entries {
            Entries::One(first) | Entries::Two { first, .. } => first,
        }
    }

    /// The payload of `entry`, the entry of the block holding `position`.
    #[inline]
    fn payload(&self, entry: &Parsed, position: usize) -> Option<&'lookup [u8]> {
        let (block, _) = self.layout.place(position)?;
        let len = codec::payload_len(self.layout.block_len(block)?, entry.frame().width)?;
        entry.payload(self.bytes, len)
    }

    /// Byte range of the message at `position`, read from the first entry, to the next message's
    /// start, read from the last, or to the mailbox end for the last message. `None` for a
    /// range that would run backwards or past the `mailbox` length.
    #[inline]
    fn span(&self, position: usize, mailbox: usize) -> Option<Range<usize>> {
        let following = position.checked_add(1)?;
        let (start, end) = if self.layout.is_last(position) {
            let end = narrow(self.layout.fingerprint.len())?;
            (self.start(self.first(), position)?, end)
        } else {
            match &self.entries {
                Entries::One(_) => self.start_pair(position)?,
                Entries::Two { first, last } => {
                    (self.start(first, position)?, self.start(last, following)?)
                },
            }
        };
        Layout::bounded(start, end, mailbox)
    }

    /// Start of the message at `position`, which lies in `entry`'s block.
    #[inline]
    fn start(&self, entry: &Parsed, position: usize) -> Option<usize> {
        narrow(entry.frame().start(
            self.payload(entry, position)?,
            self.layout.place(position)?.1,
        )?)
    }

    /// Starts of the message at `position` and of the next one, both in the first entry's block.
    #[inline]
    fn start_pair(&self, position: usize) -> Option<(usize, usize)> {
        let payload = self.payload(self.first(), position)?;
        let (_, within) = self.layout.place(position)?;
        let (start, next) = self.first().frame().start_pair(payload, within)?;
        Some((narrow(start)?, narrow(next)?))
    }
}

#[expect(
    clippy::multiple_inherent_impl,
    reason = "the loaders live beside the trust check they depend on in `trust`"
)]
impl Index {
    /// The bytes and header lookups read now: the rebuild once one ran, else the original.
    fn active(&self) -> (&[u8], &Layout) {
        self.replacement.get().map_or_else(
            || (self.original.bytes(), &self.layout),
            |(bytes, layout)| (bytes.as_slice(), layout),
        )
    }

    /// Indexes every message in `contents`, scanning it window by window and reading each Date
    /// header on all rayon threads, in blocks of 256 messages.
    ///
    /// A message starts at a line beginning with `From `, matching Python's `mailbox.mbox`; a
    /// message without a parsable Date header reads back as `None`, not zero; a real date of the
    /// epoch is `Some(0)`.
    #[must_use]
    pub fn build(contents: Arc<Mmap>, fingerprint: Fingerprint) -> Self {
        Self::build_with(contents, fingerprint, BlockSize::default())
    }

    /// As [`Index::build`], with blocks of `block_size.entries()` messages.
    #[must_use]
    pub fn build_with(
        contents: Arc<Mmap>,
        fingerprint: Fingerprint,
        block_size: BlockSize,
    ) -> Self {
        let (bytes, layout) = encoded(&contents, fingerprint, block_size, Parallelism::Parallel);
        Self::new(contents, Backing::Owned(bytes), layout, None)
    }

    /// Size of the index by section, over the rebuild once one ran.
    ///
    /// Entries are read without checking their blocks, so this rebuilds only when a directory
    /// entry is refused: a refused entry is never counted as a smaller section.
    ///
    /// # Panics
    ///
    /// Only if a directory entry of the freshly encoded rebuild were refused. The encoder writes
    /// every entry and sizes every payload itself, so the rebuild's entries are always within
    /// its directories and the rebuild always measures.
    #[must_use]
    pub fn bytes(&self) -> IndexBytes {
        #[expect(
            clippy::expect_used,
            reason = "a rebuild's entries were just written by the encoder, so none is refused"
        )]
        let sections = measured(self.active()).unwrap_or_else(|| {
            measured(self.rebuilt()).expect("a rebuilt index has no refused directory entry")
        });
        sections
    }

    /// [`Index::span`] the long way: verifying the blocks it reaches the first time, and
    /// answering from the rebuild once one ran or when the original cannot answer.
    #[cold]
    #[inline(never)]
    fn checked_span(&self, position: usize) -> Option<Range<usize>> {
        let mailbox = self.mailbox.len();
        let needed = position..position.saturating_add(2);
        self.lookup(Section::Starts, needed, |reach| {
            reach.span(position, mailbox)
        })
    }

    /// A cursor that walks the spans of consecutive positions one block at a time.
    pub(crate) const fn cursor(&self) -> Cursor<'_> {
        Cursor::new(self)
    }

    /// Date of the message at `position` in unix seconds, or `None` when it has no parsable Date
    /// header or `position` is past the last message. A Date of exactly the Unix epoch is
    /// `Some(0)`.
    #[must_use]
    pub fn date(&self, position: usize) -> Option<i64> {
        let needed = position..position.saturating_add(1);
        self.lookup(Section::Dates, needed, |reach| reach.date(position))
            .flatten()
    }

    /// Decodes into `bounds` the starts of original `block`, after verifying it and the block
    /// that follows, then where the block's last message ends. `None` when the block or its
    /// successor is damaged. `bounds` is left empty when they run backwards or past the
    /// mapping, so every span of the block is answered by [`Index::span`].
    fn decode(&self, block: usize, bounds: &mut Vec<u64>) -> Option<()> {
        #[cfg(test)]
        #[expect(unused_results, reason = "the previous count is not needed")]
        self.decoded.fetch_add(1, Ordering::Relaxed);
        let entry = self.entry(Section::Starts, block)?;
        let count = self.layout.block_len(block)?;
        let len = codec::payload_len(count, entry.frame().width)?;
        let payload = entry.payload(self.original.bytes(), len)?;
        codec::starts(entry.frame(), payload, count, bounds)?;
        bounds.push(widen(self.end_of(block)?));
        let inside = bounds
            .first()
            .zip(bounds.last())
            .and_then(|(&first, &end)| {
                Layout::bounded(narrow(first)?, narrow(end)?, self.mailbox.len())
            });
        if inside.is_none() || !bounds.is_sorted() {
            bounds.clear();
        }
        Some(())
    }

    /// Starts blocks decoded by cursors so far.
    #[cfg(test)]
    pub(crate) fn decoded_blocks(&self) -> usize {
        self.decoded.load(Ordering::Relaxed)
    }

    /// The first start of the block after `block`, or the mailbox length after the last block.
    fn end_of(&self, block: usize) -> Option<usize> {
        let next = block.checked_add(1)?;
        if self.layout.is_last(self.layout.last_in_block(block)?) {
            return narrow(self.layout.fingerprint.len());
        }
        let entry = self.entry(Section::Starts, next)?;
        narrow(entry.start(self.original.bytes(), 0)?)
    }

    /// The cache of parsed entries of `section`, one cell per block.
    fn entries(&self, section: Section) -> &[Cell] {
        match section {
            Section::Dates => &self.dates_entries,
            Section::Starts => &self.starts_entries,
        }
    }

    /// The parsed entry of original `section` block `block`, parsed and checked against its
    /// checksum only the first time. `None`, caching nothing, when the layout refuses the entry
    /// or the check fails, so every later lookup into the block fails the same way.
    #[inline]
    fn entry(&self, section: Section, block: usize) -> Option<Parsed> {
        let cell = self.entries(section).get(block)?;
        cell.load().or_else(|| self.parse(section, block, cell))
    }

    /// Identity of the mailbox this index describes.
    #[must_use]
    pub const fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    /// Whether the mailbox holds no messages.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of messages, as counted by the rebuild once one ran.
    #[must_use]
    pub fn len(&self) -> usize {
        self.active().1.count
    }

    /// Answers `read` from the original bytes when the `section` blocks of every message in
    /// `needed` that exists pass their checksums, and from the rebuild otherwise, or when the
    /// original answers `None` for a message it claims to hold. `None` when `needed` starts past
    /// the last message.
    #[inline]
    fn lookup<T, F>(&self, section: Section, needed: Range<usize>, read: F) -> Option<T>
    where
        F: Fn(&Reach<'_>) -> Option<T>,
    {
        if let Some((bytes, layout)) = self.replacement.get() {
            return unchecked((bytes, layout), section, &needed, read);
        }
        if needed.start >= self.layout.count {
            return None;
        }
        self.reach(section, &needed)
            .and_then(|reach| read(&reach))
            .or_else(|| unchecked(self.rebuilt(), section, &needed, read))
    }

    /// An index over `original`, whose header is `layout`, with no block verified yet.
    fn new(mailbox: Arc<Mmap>, original: Backing, layout: Layout, origin: Option<PathBuf>) -> Self {
        Self {
            #[cfg(test)]
            decoded: AtomicUsize::new(0),
            dates_entries: cells(layout.blocks()),
            fingerprint: layout.fingerprint,
            layout,
            mailbox,
            origin,
            original,
            replacement: OnceLock::new(),
            rewrite: OnceLock::new(),
            starts_entries: cells(layout.blocks()),
        }
    }

    /// Parses the entry of original `section` block `block` and, when its block passes its
    /// checksum, keeps it in `cell`. A concurrent caller may check the block too; any thread may
    /// store, and every store writes the same bits, so both get the entry.
    #[cold]
    fn parse(&self, section: Section, block: usize, cell: &Cell) -> Option<Parsed> {
        let bytes = self.original.bytes();
        let (entry, payload) = self.layout.entry_at(bytes, section, block)?;
        if !codec::verify(&entry, bytes.get(payload.clone())?) {
            return None;
        }
        let parsed = Parsed::new((entry, payload));
        cell.store(parsed)?;
        Some(parsed)
    }

    /// The parsed, checked entries of the blocks holding the first and the last message of
    /// `needed` that exists, `None` when either block fails its check.
    #[inline]
    fn reach(&self, section: Section, needed: &Range<usize>) -> Option<Reach<'_>> {
        let (first_block, last_block) = blocks_of(&self.layout, needed)?;
        let first = self.entry(section, first_block)?;
        let entries = if last_block == first_block {
            Entries::One(first)
        } else {
            Entries::Two {
                first,
                last: self.entry(section, last_block)?,
            }
        };
        Some(Reach {
            bytes: self.original.bytes(),
            entries,
            layout: &self.layout,
        })
    }

    /// Rescans the mailbox and, when the index was loaded from a file, rewrites that file with
    /// the result and keeps the outcome for [`Index::rewrite_outcome`].
    ///
    /// A lookup that finds a damaged block runs this inside `replacement`'s `get_or_init`, and
    /// the lookup may be on a rayon worker, as in [`crate::Mailbox::par_iter`]. A worker that
    /// forks here would steal lookups that wait on the same `get_or_init`, so the rebuild
    /// encodes on the calling thread whenever it is a worker.
    fn rebuild(&self) -> (Vec<u8>, Layout) {
        let parallelism = if rayon::current_thread_index().is_some() {
            Parallelism::Sequential
        } else {
            Parallelism::Parallel
        };
        let (bytes, layout) = encoded(
            &self.mailbox,
            self.fingerprint,
            self.layout.block_size,
            parallelism,
        );
        if let Some(origin) = &self.origin {
            #[expect(
                unused_results,
                reason = "the outcome is kept in `rewrite` for rewrite_outcome; a failed rewrite \
                          leaves lookups answered from memory, which is still correct"
            )]
            self.rewrite
                .get_or_init(|| write_atomically(origin, &bytes));
        }
        (bytes, layout)
    }

    /// The rebuild, running it first when no lookup has; concurrent callers wait for one run.
    fn rebuilt(&self) -> (&[u8], &Layout) {
        let (bytes, layout) = self.replacement.get_or_init(|| self.rebuild());
        (bytes, layout)
    }

    /// Whether a rebuild rewrote the file the index was loaded from: `None` until a rebuild of
    /// a loaded index ran, else the outcome of the rename into place.
    pub(crate) fn rewrite_outcome(&self) -> Option<Result<(), &io::Error>> {
        self.rewrite.get().map(|outcome| outcome.as_ref().copied())
    }

    /// Writes the index to `path` atomically, staging a temporary file beside it and renaming
    /// it into place, so readers and existing mappings see the old file or the new one, never a
    /// partial write. After a rebuild the rebuilt bytes are written.
    ///
    /// # Errors
    ///
    /// [`MboxTurboError::Io`] when the temporary file cannot be created, written, synced, or
    /// renamed into place.
    pub fn save(&self, path: &Path) -> Result<(), MboxTurboError> {
        write_atomically(path, self.active().0).map_err(|source| MboxTurboError::io(path, source))
    }

    /// Byte range of the message at `position`, from its start to the next message's start or
    /// to the end of the mailbox for the last message, or `None` past the last message.
    #[must_use]
    #[inline]
    pub fn span(&self, position: usize) -> Option<Range<usize>> {
        self.verified_span(position)
            .or_else(|| self.checked_span(position))
    }

    /// Byte range covering the messages at `positions`, clamped to the messages that exist.
    #[must_use]
    pub fn span_of(&self, positions: Range<usize>) -> Option<Range<usize>> {
        let first = self.span(positions.start)?;
        let last = positions
            .end
            .checked_sub(1)
            .and_then(|end| self.span(end.min(self.len().checked_sub(1)?)))?;
        (first.start < last.end).then_some(first.start..last.end)
    }

    /// Blocks of `section` whose checksum a lookup has checked and accepted.
    #[cfg(test)]
    pub(crate) fn verified_blocks(&self, section: Section) -> usize {
        self.entries(section)
            .iter()
            .filter(|cell| cell.is_filled())
            .count()
    }

    /// [`Index::verified_span`] for the last message of a block or of the mailbox, as the start
    /// at `within` of `entry`'s block and the start that follows it: the next block's first
    /// start from its cached entry, or the mailbox end after the last message. `None` when the
    /// next block has no cached entry yet or a read is refused.
    #[inline(never)]
    fn verified_edge(&self, entry: Parsed, position: usize, within: usize) -> Option<(u64, u64)> {
        let bytes = self.original.bytes();
        let start = entry.start(bytes, within)?;
        if self.layout.is_last(position) {
            return Some((start, self.layout.fingerprint.len()));
        }
        let following = position.checked_add(1)?;
        let (block, _) = self.layout.place(following)?;
        let next = self.starts_entries.get(block)?.load()?;
        Some((start, next.start(bytes, 0)?))
    }

    /// [`Index::span`] from the cached entries of verified original blocks alone, both starts
    /// from one 16-byte load unless the message ends its block: `None` once a rebuild ran, past
    /// the last message, when a block it needs has no cached entry yet, or whenever
    /// [`codec::Frame::start_pair_at`] or the range checks refuse, so that
    /// [`Index::checked_span`] decides. Any span it answers is the one `checked_span` answers.
    #[inline]
    fn verified_span(&self, position: usize) -> Option<Range<usize>> {
        let count = self.layout.count;
        if self.replacement.get().is_some() || position >= count {
            return None;
        }
        let (block, within) = self.layout.place(position)?;
        let entry = self.starts_entries.get(block)?.load()?;
        let (first, next) = self.verified_starts(entry, position, within)?;
        Layout::bounded(narrow(first)?, narrow(next)?, self.mailbox.len())
    }

    /// The starts at `within` and after it that [`Index::verified_span`] needs: both from one
    /// load of `entry`'s block unless the message at `position` ends its block or the mailbox.
    #[inline]
    fn verified_starts(&self, entry: Parsed, position: usize, within: usize) -> Option<(u64, u64)> {
        let ends_block = self.layout.place(position.checked_add(1)?)?.1 == 0;
        if self.layout.is_last(position) || ends_block {
            self.verified_edge(entry, position, within)
        } else {
            entry.start_pair(self.original.bytes(), within)
        }
    }
}

/// The blocks holding the first message of `needed` and the last one that exists, in an index
/// whose header is `layout`; `None` when `needed` starts past the last message.
#[inline]
fn blocks_of(layout: &Layout, needed: &Range<usize>) -> Option<(usize, usize)> {
    let count = layout.count;
    if needed.start >= count {
        return None;
    }
    let last = needed.end.min(count).checked_sub(1)?.max(needed.start);
    Some((layout.place(needed.start)?.0, layout.place(last)?.0))
}

/// One empty cell per block of `blocks`; nothing is parsed until a lookup reaches a block.
fn cells(blocks: usize) -> Box<[Cell]> {
    iter::repeat_with(Cell::empty).take(blocks).collect()
}

/// Size of the index in `bytes` by section, or `None` when a directory entry is refused.
fn measured((bytes, layout): (&[u8], &Layout)) -> Option<IndexBytes> {
    let directory = layout
        .blocks()
        .saturating_mul(2)
        .saturating_mul(format::ENTRY_LEN);
    Some(IndexBytes {
        dates: section_bytes(layout, bytes, Section::Dates)?,
        directory: widen(directory),
        header: widen(format::HEADER_LEN),
        starts: section_bytes(layout, bytes, Section::Starts)?,
    })
}

/// Payload bytes of every block of `section`, read from the directory entries alone, or `None`
/// on the first entry that is refused.
fn section_bytes(layout: &Layout, bytes: &[u8], section: Section) -> Option<u64> {
    (0..layout.blocks()).try_fold(0_u64, |total, block| {
        let (entry, _) = layout.entry_at(bytes, section, block)?;
        let payload = codec::payload_len(layout.block_len(block)?, entry.width)?;
        total.checked_add(widen(payload))
    })
}

/// Answers `read` from the rebuilt `bytes` whose header is `layout`, parsing the entries it needs
/// without checking them, since a rebuild is never re-verified. `None` when `needed` starts past
/// the last message or the rebuild cannot answer.
fn unchecked<T, F>(
    (bytes, layout): (&[u8], &Layout),
    section: Section,
    needed: &Range<usize>,
    read: F,
) -> Option<T>
where
    F: Fn(&Reach<'_>) -> Option<T>,
{
    let (first_block, last_block) = blocks_of(layout, needed)?;
    let first = Parsed::new(layout.entry_at(bytes, section, first_block)?);
    let entries = if first_block == last_block {
        Entries::One(first)
    } else {
        Entries::Two {
            first,
            last: Parsed::new(layout.entry_at(bytes, section, last_block)?),
        }
    };
    read(&Reach {
        bytes,
        entries,
        layout,
    })
}

/// Writes `bytes` to a temporary file beside `path`, syncs it and renames it over `path`.
fn write_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let mut staged = NamedTempFile::new_in(directory.unwrap_or_else(|| Path::new(".")))?;
    staged.write_all(bytes)?;
    staged.as_file().sync_all()?;
    staged
        .persist(path)
        .map(|_persisted| ())
        .map_err(|failure| failure.error)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::ops::Range;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::thread;

    use memmap2::Mmap;
    use proptest::collection::vec;
    use proptest::prelude::*;
    use tempfile::TempDir;

    use super::{BlockSize, Index, Section, format};
    use crate::error::MboxTurboError;
    use crate::fingerprint::Fingerprint;
    use crate::mapping::map_read_only;
    use crate::scan;
    use crate::width::{narrow, widen};

    /// Messages in the fixture: two full blocks of 256 and a short third block.
    const MESSAGES: usize = 600;

    /// A mailbox mapped from a temporary directory that also holds its index file.
    struct Fixture {
        /// The bytes of the mailbox.
        contents: Vec<u8>,
        /// The directory holding the mailbox and its index, removed on drop.
        dir: TempDir,
        /// Identity of the mailbox.
        fingerprint: Fingerprint,
        /// The mapped mailbox.
        mailbox: Arc<Mmap>,
    }

    impl Fixture {
        fn built(&self) -> Index {
            Index::build(Arc::clone(&self.mailbox), self.fingerprint)
        }

        /// Overwrites the index file in place with `byte` flipped.
        fn damage(&self, byte: usize) {
            let path = self.index_path();
            let mut bytes = fs::read(&path).expect("the saved index reads back");
            bytes[byte] ^= 0xFF;
            fs::write(&path, bytes).expect("the damaged index is written back");
        }

        /// Where the entry of starts block `block` begins in the saved index.
        fn entry_at(&self, block: usize) -> usize {
            let bytes = fs::read(self.index_path()).expect("the saved index reads back");
            let layout =
                format::Layout::parse(&bytes, self.fingerprint).expect("the saved header is valid");
            let directory = narrow(layout.dir_offset).expect("the offset fits usize");
            let skipped = block
                .checked_mul(format::ENTRY_LEN)
                .expect("test blocks are few");
            plus(directory, skipped)
        }

        /// The span of every message, from a scan of the mailbox.
        fn expected(&self) -> Vec<Range<usize>> {
            let starts = scan::find_message_starts(&self.contents);
            let ends = starts.iter().skip(1).copied().chain([self.contents.len()]);
            starts
                .iter()
                .copied()
                .zip(ends)
                .map(|(start, end)| start..end)
                .collect()
        }

        fn index_path(&self) -> PathBuf {
            self.dir.path().join("mbox.idx")
        }

        fn loaded(&self) -> Index {
            Index::load(
                &self.index_path(),
                Arc::clone(&self.mailbox),
                self.fingerprint,
            )
            .expect("the saved index loads")
        }

        fn new() -> Self {
            let dir = TempDir::new().expect("a temporary directory is created");
            let contents = contents();
            let path = dir.path().join("mbox");
            fs::write(&path, &contents).expect("the fixture mailbox is written");
            let file = File::open(&path).expect("the fixture mailbox reopens");
            let mailbox = Arc::new(map_read_only(&file).expect("the fixture mailbox maps"));
            Self {
                fingerprint: Fingerprint::new(&contents, None),
                contents,
                dir,
                mailbox,
            }
        }

        /// Saves a freshly built index and returns its bytes.
        fn saved(&self) -> Vec<u8> {
            self.built()
                .save(&self.index_path())
                .expect("the index is saved");
            fs::read(self.index_path()).expect("the saved index reads back")
        }

        /// Every span `index` answers for the fixture's positions.
        fn spans(index: &Index) -> Vec<Range<usize>> {
            (0..MESSAGES)
                .filter_map(|position| index.span(position))
                .collect()
        }
    }

    /// A mailbox on disk with its index in blocks of `2^shift` messages, from which indexes are
    /// loaded over any bytes.
    struct Disk {
        /// The directory holding the files, removed on drop.
        dir: TempDir,
        /// The span of every message, from a scan of the mailbox.
        expected: Vec<Range<usize>>,
        /// Identity of the mailbox.
        fingerprint: Fingerprint,
        /// The index file a built index saved, valid.
        good: Vec<u8>,
        /// The mapped mailbox.
        mailbox: Arc<Mmap>,
        /// The block shift of the index.
        shift: u8,
    }

    impl Disk {
        /// `good` with the checksum of starts block `block` flipped, so the block fails its check.
        fn damaged(&self, block: usize) -> Vec<u8> {
            let layout = format::Layout::parse(&self.good, self.fingerprint)
                .expect("the saved header is valid");
            let entry = plus(
                narrow(layout.dir_offset).expect("the offset fits usize"),
                block
                    .checked_mul(format::ENTRY_LEN)
                    .expect("test blocks are few"),
            );
            let mut bytes = self.good.clone();
            bytes[plus(entry, 16)] ^= 0xFF;
            bytes
        }

        /// A fresh index loaded from `bytes`, with no block verified yet.
        fn load(&self, bytes: &[u8]) -> Index {
            let path = self.dir.path().join("mbox.idx");
            fs::write(&path, bytes).expect("the index file is written");
            Index::load(&path, Arc::clone(&self.mailbox), self.fingerprint)
                .expect("the index loads")
        }

        fn new(contents: &[u8], shift: u8) -> Self {
            let dir = TempDir::new().expect("a temporary directory is created");
            let path = dir.path().join("mbox");
            fs::write(&path, contents).expect("the mailbox is written");
            let file = File::open(&path).expect("the mailbox reopens");
            let mailbox = Arc::new(map_read_only(&file).expect("the mailbox maps"));
            let fingerprint = Fingerprint::new(contents, None);
            let block_size = BlockSize::from_shift(shift).expect("the shift is within the range");
            let good = Index::build_with(Arc::clone(&mailbox), fingerprint, block_size)
                .active()
                .0
                .to_vec();
            let starts = scan::find_message_starts(contents);
            let ends = starts.iter().skip(1).copied().chain([contents.len()]);
            let expected = starts
                .iter()
                .copied()
                .zip(ends)
                .map(|(start, end)| start..end)
                .collect();
            Self {
                dir,
                expected,
                fingerprint,
                good,
                mailbox,
                shift,
            }
        }
    }

    /// `left + right` for test offsets that cannot overflow.
    fn plus(left: usize, right: usize) -> usize {
        left.checked_add(right).expect("test offsets are small")
    }

    /// A mailbox of [`MESSAGES`] messages in which every seventh has no Date header.
    fn contents() -> Vec<u8> {
        (0..MESSAGES)
            .flat_map(|number| {
                let date = if number.rem_euclid(7) == 0 {
                    String::new()
                } else {
                    let minute = number.rem_euclid(60);
                    format!("Date: Mon, 01 Jan 2024 12:{minute:02}:00 +0000\n")
                };
                let body = "x".repeat(number.rem_euclid(40));
                format!("From a@b\n{date}Subject: {number}\n\n{body}\n").into_bytes()
            })
            .collect()
    }

    /// Where the payload of starts block `block` begins, read from its directory entry.
    fn payload_at(fixture: &Fixture, block: usize) -> usize {
        let bytes = fs::read(fixture.index_path()).expect("the saved index reads back");
        let field = plus(fixture.entry_at(block), 8);
        let word: [u8; 8] = bytes[field..plus(field, 8)]
            .try_into()
            .expect("an entry field is eight bytes");
        narrow(u64::from_le_bytes(word)).expect("the payload offset fits usize")
    }

    /// The inode of the fixture's index file, which a rename into place changes.
    #[cfg(unix)]
    fn inode(fixture: &Fixture) -> u64 {
        use std::os::unix::fs::MetadataExt as _;

        fs::metadata(fixture.index_path())
            .expect("the index file exists")
            .ino()
    }

    /// Damages the saved index at `byte`, then checks that the first lookup into the damaged
    /// block rebuilds the index, renames the rebuilt file into place and answers correctly, and
    /// that no later lookup renames another file into place.
    #[cfg(unix)]
    fn assert_one_rebuild(fixture: &Fixture, byte: usize) {
        fixture.damage(byte);
        let index = fixture.loaded();
        let damaged = inode(fixture);
        let expected = fixture.expected();
        assert_eq!(
            index.span(300),
            Some(expected[300].clone()),
            "the damaged block is rebuilt"
        );
        assert!(
            matches!(index.rewrite_outcome(), Some(Ok(()))),
            "the rebuild rewrote the file it was loaded from"
        );
        let rewritten = inode(fixture);
        assert_ne!(
            rewritten, damaged,
            "the rewrite renamed a new file into place"
        );
        assert_eq!(
            Fixture::spans(&index),
            expected,
            "every span comes from the rebuild"
        );
        assert_eq!(
            inode(fixture),
            rewritten,
            "later lookups do not rebuild again"
        );
    }

    #[test]
    fn a_loaded_index_equals_the_index_it_was_saved_from() {
        let fixture = Fixture::new();
        let _bytes = fixture.saved();
        assert_eq!(fixture.loaded(), fixture.built(), "load(save(x)) == x");
    }

    #[test]
    fn a_cursor_walking_forward_decodes_each_starts_block_once() {
        let fixture = Fixture::new();
        let index = fixture.built();
        let mut cursor = index.cursor();
        let walked: Vec<_> = (0..MESSAGES)
            .filter_map(|position| cursor.span(position))
            .collect();
        assert_eq!(walked, fixture.expected(), "the cursor answers every span");
        assert_eq!(index.decoded_blocks(), 3, "600 messages fill three blocks");
    }

    #[test]
    fn a_cursor_walking_backward_decodes_each_starts_block_once() {
        let fixture = Fixture::new();
        let index = fixture.built();
        let mut cursor = index.cursor();
        let walked: Vec<_> = (0..MESSAGES)
            .rev()
            .filter_map(|position| cursor.span(position))
            .collect();
        let mut expected = fixture.expected();
        expected.reverse();
        assert_eq!(walked, expected, "the cursor answers every span in reverse");
        assert_eq!(index.decoded_blocks(), 3, "each block is decoded once");
    }

    #[test]
    fn a_cursor_alternating_between_two_blocks_decodes_each_of_them_once() {
        let fixture = Fixture::new();
        let index = fixture.built();
        let mut cursor = index.cursor();
        for position in 0..10 {
            let _front = cursor.span(position);
            let _back = cursor.span(MESSAGES - 1 - position);
        }
        assert_eq!(
            index.decoded_blocks(),
            2,
            "the two cached blocks serve both ends"
        );
    }

    #[test]
    fn a_cursor_answers_none_past_the_last_message() {
        let fixture = Fixture::new();
        let index = fixture.built();
        assert_eq!(
            index.cursor().span(MESSAGES),
            None,
            "no message sits past the end"
        );
    }

    #[test]
    fn a_damaged_directory_entry_is_measured_from_the_rebuild() {
        let fixture = Fixture::new();
        let _bytes = fixture.saved();
        let clean = fixture.loaded().bytes();
        let high_byte = plus(fixture.entry_at(0), 15);
        fixture.damage(high_byte);
        let index = fixture.loaded();
        let (bytes, layout) = index.active();
        assert_eq!(
            super::section_bytes(layout, bytes, Section::Starts),
            None,
            "the damaged payload offset lies outside the file, so the entry is refused"
        );
        assert_eq!(
            index.bytes(),
            clean,
            "the refused entry is measured from the rebuild, not skipped"
        );
        assert!(
            index.replacement.get().is_some(),
            "the measurement ran the rebuild"
        );
    }

    #[test]
    fn a_cursor_over_a_damaged_block_answers_from_the_rebuild() {
        let fixture = Fixture::new();
        let _bytes = fixture.saved();
        fixture.damage(payload_at(&fixture, 1));
        let index = fixture.loaded();
        let mut cursor = index.cursor();
        let walked: Vec<_> = (0..MESSAGES)
            .filter_map(|position| cursor.span(position))
            .collect();
        assert_eq!(
            walked,
            fixture.expected(),
            "the damaged block is answered by the rescan"
        );
    }

    #[test]
    fn spans_cover_each_message_and_the_last_runs_to_the_end() {
        let fixture = Fixture::new();
        let _bytes = fixture.saved();
        let index = fixture.loaded();
        assert_eq!(
            Fixture::spans(&index),
            fixture.expected(),
            "each span runs to the next start or to the end of the mailbox"
        );
        assert_eq!(
            index.span(MESSAGES),
            None,
            "a position past the last message has no span"
        );
    }

    #[test]
    fn ranges_of_messages_span_from_the_first_start_to_the_last_end() {
        let fixture = Fixture::new();
        let index = fixture.built();
        let expected = fixture.expected();
        assert_eq!(
            index.span_of(0..MESSAGES),
            Some(0..fixture.contents.len()),
            "a range over every message spans the whole mailbox"
        );
        assert_eq!(
            index.span_of(599..900),
            Some(expected[599].clone()),
            "a range running past the last message is clamped to the mailbox end"
        );
        assert_eq!(index.span_of(3..3), None, "an empty range covers no bytes");
    }

    #[test]
    fn a_message_without_a_date_has_none() {
        let index = Fixture::new().built();
        assert_eq!(index.date(7), None, "message 7 has no Date header");
    }

    #[test]
    fn a_date_header_is_read_as_unix_seconds() {
        let index = Fixture::new().built();
        assert_eq!(
            index.date(1),
            Some(1_704_110_460),
            "Mon, 01 Jan 2024 12:01:00 +0000 in unix seconds"
        );
    }

    #[test]
    fn a_position_past_the_last_message_has_no_date() {
        let index = Fixture::new().built();
        assert_eq!(index.date(MESSAGES), None, "only 600 messages exist");
    }

    #[test]
    fn an_index_for_a_different_mailbox_is_stale() {
        let fixture = Fixture::new();
        let _bytes = fixture.saved();
        let other = Fingerprint::new(b"From z\n", None);
        let result = Index::load(&fixture.index_path(), Arc::clone(&fixture.mailbox), other);
        assert!(
            matches!(result, Err(MboxTurboError::StaleIndex { .. })),
            "a fingerprint mismatch is stale"
        );
    }

    #[test]
    fn saving_replaces_the_target_and_leaves_no_temporary_file() {
        let fixture = Fixture::new();
        let first = fixture.saved();
        let second = fixture.saved();
        let mut names: Vec<_> = fs::read_dir(fixture.dir.path())
            .expect("the fixture directory lists")
            .map(|entry| entry.expect("a directory entry reads").file_name())
            .collect();
        names.sort();
        assert_eq!(
            names,
            ["mbox", "mbox.idx"],
            "the staged file was renamed into place"
        );
        assert_eq!(
            first, second,
            "saving the same index twice writes the same bytes"
        );
    }

    #[test]
    fn a_lookup_verifies_its_block_once() {
        let fixture = Fixture::new();
        let _bytes = fixture.saved();
        let index = fixture.loaded();
        assert_eq!(
            index.verified_blocks(Section::Starts),
            0,
            "loading checks no block"
        );
        let _first = index.span(0);
        assert_eq!(
            index.verified_blocks(Section::Starts),
            1,
            "the first lookup checks block 0"
        );
        let _second = index.span(1);
        assert_eq!(
            index.verified_blocks(Section::Starts),
            1,
            "a second lookup into block 0 checks nothing new"
        );
    }

    #[test]
    fn a_date_lookup_verifies_only_its_dates_block() {
        let fixture = Fixture::new();
        let _bytes = fixture.saved();
        let index = fixture.loaded();
        let _date = index.date(300);
        assert_eq!(
            (
                index.verified_blocks(Section::Dates),
                index.verified_blocks(Section::Starts)
            ),
            (1, 0),
            "a date reads the dates directory alone"
        );
    }

    #[test]
    fn a_clean_lookup_does_not_rewrite_the_file() {
        let fixture = Fixture::new();
        let _bytes = fixture.saved();
        let index = fixture.loaded();
        let _span = index.span(300);
        assert!(
            index.rewrite_outcome().is_none(),
            "a sound block needs no rebuild"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_payload_corruption_triggers_exactly_one_rebuild() {
        let fixture = Fixture::new();
        let _bytes = fixture.saved();
        assert_one_rebuild(&fixture, payload_at(&fixture, 1));
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_entry_corruption_triggers_exactly_one_rebuild() {
        let fixture = Fixture::new();
        let _bytes = fixture.saved();
        assert_one_rebuild(&fixture, plus(fixture.entry_at(1), 16));
    }

    #[test]
    fn a_rebuild_rewrites_the_file_a_clean_build_would_save() {
        let fixture = Fixture::new();
        let clean = fixture.saved();
        fixture.damage(payload_at(&fixture, 1));
        let _span = fixture.loaded().span(300);
        assert_eq!(
            fs::read(fixture.index_path()).expect("the rewritten index reads back"),
            clean,
            "the rewrite holds the bytes of a fresh build"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_read_only_directory_rebuilds_in_memory() {
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = Fixture::new();
        let _bytes = fixture.saved();
        fixture.damage(plus(fixture.entry_at(1), 16));
        let index = fixture.loaded();
        let directory = fixture.dir.path();
        fs::set_permissions(directory, fs::Permissions::from_mode(0o500))
            .expect("the directory is made read-only");
        let spans = Fixture::spans(&index);
        let failed = index.rewrite_outcome().map(|outcome| outcome.is_err());
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .expect("the directory is made writable again for cleanup");
        assert_eq!(
            spans,
            fixture.expected(),
            "lookups are answered from the rebuild in memory"
        );
        assert_eq!(
            failed,
            Some(true),
            "the rewrite into a read-only directory failed"
        );
    }

    /// Looks up every position from `first` onwards, wrapping around, against `expected`.
    fn walk(index: &Index, expected: &[Range<usize>], first: usize) {
        for step in 0..MESSAGES {
            let position = plus(step, first).rem_euclid(MESSAGES);
            assert_eq!(
                index.span(position),
                expected.get(position).cloned(),
                "span {position} starting from {first}"
            );
        }
    }

    #[test]
    fn lookups_from_many_threads_during_a_rebuild_return_correct_spans() {
        let fixture = Fixture::new();
        let _bytes = fixture.saved();
        fixture.damage(payload_at(&fixture, 1));
        let index = fixture.loaded();
        let expected = fixture.expected();
        thread::scope(|scope| {
            for first in (0..MESSAGES).step_by(75) {
                let (shared, spans) = (&index, &expected);
                let _worker = scope.spawn(move || walk(shared, spans, first));
            }
        });
    }

    #[test]
    fn a_checksummed_span_past_the_mailbox_triggers_a_rebuild() {
        let fixture = Fixture::new();
        let mut starts: Vec<u64> = scan::find_message_starts(&fixture.contents)
            .into_iter()
            .map(widen)
            .collect();
        starts[599] = widen(plus(fixture.contents.len(), 10));
        let dates = vec![None; starts.len()];
        let bytes = format::encode(&starts, &dates, fixture.fingerprint, BlockSize::default())
            .expect("the forged starts encode with valid checksums");
        fs::write(fixture.index_path(), bytes).expect("the forged index is written");
        assert_eq!(
            fixture.loaded().span(598),
            Some(fixture.expected()[598].clone()),
            "a span ending past the mailbox is answered from the rebuild"
        );
    }

    /// A mailbox of `messages` messages dated every other message, with varying body lengths so
    /// message starts do not line up with segment boundaries.
    pub(super) fn dated_mailbox(messages: usize) -> Vec<u8> {
        (0..messages)
            .flat_map(|number| {
                let date = if number.rem_euclid(2) == 0 {
                    let second = number.rem_euclid(60);
                    format!("Date: Mon, 01 Jan 2024 12:00:{second:02} +0000\n")
                } else {
                    String::new()
                };
                let body = "y".repeat(number.rem_euclid(97));
                format!("From a@b\n{date}Subject: {number}\n\n{body}\n").into_bytes()
            })
            .collect()
    }

    #[test]
    fn the_sections_add_up_to_the_length_of_the_built_index() {
        let contents = dated_mailbox(1_000);
        let fingerprint = Fingerprint::new(&contents, None);
        let dir = TempDir::new().expect("a temporary directory is created");
        let path = dir.path().join("mbox");
        fs::write(&path, &contents).expect("the dated mailbox is written");
        let file = File::open(&path).expect("the dated mailbox reopens");
        let mailbox = Arc::new(map_read_only(&file).expect("the dated mailbox maps"));
        let index = Index::build_with(
            mailbox,
            fingerprint,
            BlockSize::from_shift(5).expect("5 is within the range"),
        );
        let sections = index.bytes();
        let served = index.active().0.len();
        let blocks = index.active().1.blocks();
        assert_eq!(
            sections.total(),
            widen(served),
            "header, directories and both payloads cover every served byte: {sections:?}"
        );
        assert_eq!(sections.header, 72, "the header is 72 bytes");
        assert_eq!(
            sections.directory,
            widen(blocks * 2 * 32),
            "each block has a 32-byte entry in two directories"
        );
    }

    /// Asserts that the first and the second `Index::span` of every position of `index`, and
    /// `Cursor::span` over them in order, answer the scanned span; `None` one past the end.
    fn assert_readers_agree(disk: &Disk, index: &Index) -> Result<(), TestCaseError> {
        let mut cursor = index.cursor();
        for position in 0..=disk.expected.len() {
            let expected = disk.expected.get(position).cloned();
            prop_assert_eq!(
                index.span(position),
                expected.clone(),
                "span {} first call",
                position
            );
            prop_assert_eq!(
                index.span(position),
                expected.clone(),
                "span {} second call",
                position
            );
            prop_assert_eq!(cursor.span(position), expected, "cursor span {}", position);
        }
        Ok(())
    }

    /// A mailbox whose message `n` has a body of `bodies[n]` bytes, so starts differ in gap.
    fn bodied_mailbox(bodies: &[usize]) -> Vec<u8> {
        bodies
            .iter()
            .enumerate()
            .flat_map(|(number, &len)| {
                let body = "z".repeat(len);
                format!("From a@b\nSubject: {number}\n\n{body}\n").into_bytes()
            })
            .collect()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        #[test]
        fn every_reader_answers_the_scanned_span(
            bodies in vec(0_usize..80, 1..=48),
            shift in prop_oneof![1_u8..=4, Just(BlockSize::default().shift())],
        ) {
            let disk = Disk::new(&bodied_mailbox(&bodies), shift);
            for position in 0..=disk.expected.len() {
                let cold = disk.load(&disk.good);
                let expected = disk.expected.get(position).cloned();
                prop_assert_eq!(cold.span(position), expected.clone(), "cold span {}", position);
                prop_assert_eq!(cold.span(position), expected.clone(), "warm span {}", position);
                prop_assert_eq!(
                    disk.load(&disk.good).cursor().span(position),
                    expected,
                    "cursor span {} on a fresh index",
                    position
                );
            }
            assert_readers_agree(&disk, &disk.load(&disk.good))?;
        }

        #[test]
        fn every_reader_answers_the_scanned_span_after_a_rebuild(
            bodies in vec(0_usize..80, 1..=48),
            shift in prop_oneof![1_u8..=4, Just(BlockSize::default().shift())],
            damaged in 0_usize..64,
        ) {
            let disk = Disk::new(&bodied_mailbox(&bodies), shift);
            let layout = format::Layout::parse(&disk.good, disk.fingerprint)
                .expect("the saved header is valid");
            let block = damaged.rem_euclid(layout.blocks());
            let index = disk.load(&disk.damaged(block));
            let first = block.checked_shl(u32::from(disk.shift)).expect("test shifts are small");
            let _span = index.span(first);
            prop_assert!(index.rewrite_outcome().is_some(), "the damaged block forced a rebuild");
            assert_readers_agree(&disk, &index)?;
        }
    }
}
