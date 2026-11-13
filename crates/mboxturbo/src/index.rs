//! Message boundary index over the v2 block-directory file, verified one block at a time and
//! rebuilt from the mailbox when a block turns out to be damaged.

mod codec;
mod date;
mod format;

use std::fs::File;
use std::io::{self, Write as _};
use std::ops::Range;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::{fmt, iter, mem};

use memmap2::Mmap;
use rayon::prelude::*;
use tempfile::NamedTempFile;

use self::format::{Layout, Section, Writer};
use crate::error::{Corruption, MboxTurboError};
use crate::fingerprint::Fingerprint;
use crate::mailbox::map_read_only;
use crate::scan::Parallelism;
use crate::width::{narrow, widen};
use crate::{hint, scan};

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

/// A directory entry parsed once, kept so later reads of its block skip the parse. An entry of
/// the original bytes is kept only after its block passed its checksum; its payload range was
/// checked against the directories when it was parsed.
#[derive(Debug, Clone, Copy)]
struct Parsed {
    /// Base, flags and width of the block.
    frame: codec::Frame,
    /// Where the block's payload starts in the index bytes.
    payload: usize,
}

impl Parsed {
    /// The entry `Layout::entry_at` read, without its checksum.
    const fn new((block, payload): (codec::Block, Range<usize>)) -> Self {
        Self {
            frame: block.frame(),
            payload: payload.start,
        }
    }

    /// The block's payload of `len` bytes in `bytes`, `None` when it lies past their end.
    #[inline]
    fn payload<'bytes>(&self, bytes: &'bytes [u8], len: usize) -> Option<&'bytes [u8]> {
        bytes.get(self.payload..self.payload.checked_add(len)?)
    }

    /// Start at `index` of the block, as [`codec::Frame::start_at`] reads it from `bytes`.
    #[inline]
    fn start(&self, bytes: &[u8], index: usize) -> Option<u64> {
        self.frame.start_at(bytes, self.payload, index)
    }

    /// Starts at `index` and `index + 1` of the block, as [`codec::Frame::start_pair_at`]
    /// reads them from `bytes`.
    #[inline]
    fn start_pair(&self, bytes: &[u8], index: usize) -> Option<(u64, u64)> {
        self.frame.start_pair_at(bytes, self.payload, index)
    }
}

/// One slot of an entry cache: a [`Parsed`] packed into two atomic words, empty while both are
/// zero so a table of them is zero-filled at open. `word` holds, from the top, a filled bit,
/// the flags, the width and the payload start.
#[derive(Debug)]
struct Cell {
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
    const fn empty() -> Self {
        Self {
            base: AtomicU64::new(0),
            word: AtomicU64::new(0),
        }
    }

    /// Whether an entry was stored.
    #[inline]
    fn is_filled(&self) -> bool {
        self.word.load(Ordering::Relaxed) & Self::FILLED != 0
    }

    /// The stored entry, `None` while the cell is empty.
    #[inline]
    fn load(&self) -> Option<Parsed> {
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
    fn store(&self, parsed: Parsed) -> Option<()> {
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

/// What one lookup reads: the index bytes and the parsed entries of the blocks holding the first
/// and the last message it needs, the same entry when both lie in one block.
#[derive(Debug)]
struct Reach<'lookup> {
    /// The index bytes the entries point into.
    bytes: &'lookup [u8],
    /// The entry of the block holding the first message needed.
    first: Parsed,
    /// The entry of the block holding the last message needed that exists.
    last: Parsed,
    /// The header of `bytes`.
    layout: &'lookup Layout,
    /// Whether `first` and `last` are one entry.
    same: bool,
}

impl<'lookup> Reach<'lookup> {
    /// Date of the message at `position`, read from the first entry.
    fn date(&self, position: usize) -> Option<i64> {
        self.first.frame.date(
            self.payload(&self.first, position)?,
            self.layout.place(position)?.1,
        )
    }

    /// The payload of `entry`, the entry of the block holding `position`.
    #[inline]
    fn payload(&self, entry: &Parsed, position: usize) -> Option<&'lookup [u8]> {
        let (block, _) = self.layout.place(position)?;
        let len = codec::payload_len(self.layout.block_len(block)?, entry.frame.width)?;
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
            (self.start(&self.first, position)?, end)
        } else if self.same {
            self.start_pair(position)?
        } else {
            (
                self.start(&self.first, position)?,
                self.start(&self.last, following)?,
            )
        };
        Layout::bounded(start, end, mailbox)
    }

    /// Start of the message at `position`, which lies in `entry`'s block.
    #[inline]
    fn start(&self, entry: &Parsed, position: usize) -> Option<usize> {
        narrow(entry.frame.start(
            self.payload(entry, position)?,
            self.layout.place(position)?.1,
        )?)
    }

    /// Starts of the message at `position` and of the next one, both in the first entry's block.
    #[inline]
    fn start_pair(&self, position: usize) -> Option<(usize, usize)> {
        let payload = self.payload(&self.first, position)?;
        let (_, within) = self.layout.place(position)?;
        let (start, next) = self.first.frame.start_pair(payload, within)?;
        Some((narrow(start)?, narrow(next)?))
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
    /// message without a parsable Date header is dated zero.
    #[must_use]
    pub fn build(contents: Arc<Mmap>, fingerprint: Fingerprint) -> Self {
        Self::build_with(contents, fingerprint, format::DEFAULT_BLOCK_SHIFT)
    }

    /// As [`Index::build`], with blocks of `2^block_shift` messages.
    ///
    /// # Panics
    ///
    /// When `block_shift` is outside `1..=16`, the range the file header allows.
    #[must_use]
    pub fn build_with(contents: Arc<Mmap>, fingerprint: Fingerprint, block_shift: u8) -> Self {
        let (bytes, layout) = encoded(&contents, fingerprint, block_shift, Parallelism::Parallel);
        Self::new(contents, Backing::Owned(bytes), layout, None)
    }

    /// Size of the index by section, over the rebuild once one ran.
    ///
    /// Entries are read without checking their blocks, so this never triggers a rebuild.
    #[must_use]
    pub fn bytes(&self) -> IndexBytes {
        let (bytes, layout) = self.active();
        let directory = layout
            .blocks()
            .saturating_mul(2)
            .saturating_mul(format::ENTRY_LEN);
        IndexBytes {
            dates: section_bytes(layout, bytes, Section::Dates),
            directory: widen(directory),
            header: widen(format::HEADER_LEN),
            starts: section_bytes(layout, bytes, Section::Starts),
        }
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
        Cursor {
            index: self,
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

    /// Date of the message at `position` in unix seconds, `Some(0)` when it has no parsable
    /// Date header, or `None` past the last message.
    #[must_use]
    pub fn date(&self, position: usize) -> Option<i64> {
        let needed = position..position.saturating_add(1);
        self.lookup(Section::Dates, needed, |reach| reach.date(position))
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
        let len = codec::payload_len(count, entry.frame.width)?;
        let payload = entry.payload(self.original.bytes(), len)?;
        codec::starts(&entry.frame, payload, count, bounds)?;
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
        messages(self.active().1)
    }

    /// Maps the index file at `path` and checks its header against the mailbox `expected`
    /// identifies, whose mapping `mailbox` is kept for a rebuild. Only the header is read here;
    /// blocks are checked when lookups reach them.
    ///
    /// # Errors
    ///
    /// [`MboxTurboError::Io`] when the file cannot be opened or mapped,
    /// [`MboxTurboError::CorruptIndex`] when its header or length fails validation, and
    /// [`MboxTurboError::StaleIndex`] when it was written by an older format or for a different
    /// mailbox than `expected`.
    pub fn load(
        path: &Path,
        mailbox: Arc<Mmap>,
        expected: Fingerprint,
    ) -> Result<Self, MboxTurboError> {
        let file = File::open(path).map_err(|source| MboxTurboError::io(path, source))?;
        let mapped = map_read_only(&file).map_err(|source| MboxTurboError::io(path, source))?;
        let layout = Layout::parse(&mapped, expected).map_err(|rejection| rejection.at(path))?;
        let origin = Some(path.to_path_buf());
        Ok(Self::new(mailbox, Backing::Mapped(mapped), layout, origin))
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
        if needed.start >= messages(&self.layout) {
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
    /// checksum, keeps it in `cell`. A concurrent caller may check the block too; the first to
    /// finish fills the cell and both get its entry.
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
        let same = last_block == first_block;
        let last = if same {
            first
        } else {
            self.entry(section, last_block)?
        };
        Some(Reach {
            bytes: self.original.bytes(),
            first,
            last,
            same,
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
            self.layout.block_shift,
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
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "read by the cache statistics once T11 lands")
    )]
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
        let count = messages(&self.layout);
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

/// Encodes the messages whose starts arrive window by window, keeping only one block of starts
/// and dates in memory beside the window in hand.
///
/// A window's last message has no successor yet, so it waits in `carry` until the next window
/// supplies the start its slice runs to.
struct Streamer<'sink> {
    /// The start of the newest message, whose end is not known yet.
    carry: Option<usize>,
    /// The mailbox the starts point into.
    contents: &'sink [u8],
    /// Dates of the messages in `starts`.
    dates: Vec<i64>,
    /// Whether dating a window uses the rayon pool.
    parallelism: Parallelism,
    /// Messages in a full block.
    per_block: usize,
    /// Starts of the messages not yet pushed to `writer`.
    starts: Vec<u64>,
    /// The index file being written.
    writer: Writer<&'sink mut io::Cursor<Vec<u8>>>,
}

impl Streamer<'_> {
    /// Takes the next window of ascending starts, dating every message whose successor is now
    /// known and pushing each block that fills.
    fn feed(&mut self, window: Vec<usize>) -> io::Result<()> {
        let run: Vec<usize> = self.carry.take().into_iter().chain(window).collect();
        let Some((&last, head)) = run.split_last() else {
            return Ok(());
        };
        self.dates
            .extend(dates_before_last(self.contents, &run, self.parallelism)?);
        self.starts.extend(head.iter().map(|&start| widen(start)));
        self.carry = Some(last);
        self.flush_full()
    }

    /// Dates the newest message to the end of the mailbox and pushes the final block.
    fn finish(mut self) -> io::Result<()> {
        if let Some(last) = self.carry.take() {
            self.dates
                .push(message_date(self.contents, last, self.contents.len())?);
            self.starts.push(widen(last));
        }
        self.flush_full()?;
        if !self.starts.is_empty() {
            self.writer.push(&self.starts, &self.dates)?;
        }
        self.writer.finish().map(|_count| ())
    }

    /// Pushes every full block of `starts` and `dates` and keeps the remainder.
    fn flush_full(&mut self) -> io::Result<()> {
        let starts = self.starts.chunks_exact(self.per_block);
        let dates = self.dates.chunks_exact(self.per_block);
        let full = self.starts.len().saturating_sub(starts.remainder().len());
        for (block_starts, block_dates) in starts.zip(dates) {
            self.writer.push(block_starts, block_dates)?;
        }
        self.starts.drain(..full).for_each(drop);
        self.dates.drain(..full).for_each(drop);
        Ok(())
    }
}

/// The blocks holding the first message of `needed` and the last one that exists, in an index
/// whose header is `layout`; `None` when `needed` starts past the last message.
#[inline]
fn blocks_of(layout: &Layout, needed: &Range<usize>) -> Option<(usize, usize)> {
    let count = messages(layout);
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

/// Dates in unix seconds of every message of `run` but the last, each running to the next start,
/// zero for a message without a parsable Date header.
fn dates_before_last(
    contents: &[u8],
    run: &[usize],
    parallelism: Parallelism,
) -> io::Result<Vec<i64>> {
    let date = |(&start, &end): (&usize, &usize)| message_date(contents, start, end);
    match parallelism {
        Parallelism::Parallel => run
            .par_iter()
            .zip(run.par_iter().skip(1))
            .map(date)
            .collect(),
        Parallelism::Sequential => run.iter().zip(run.iter().skip(1)).map(date).collect(),
    }
}

/// The index file for `contents` with blocks of `2^block_shift` messages, with its header.
#[expect(
    clippy::expect_used,
    reason = "the scanner's starts ascend below the mailbox length, the block shift is the \
              caller's documented 1..=16, and a file the writer finished for `fingerprint` \
              has a header that parses for `fingerprint`; each is all the writer refuses"
)]
fn encoded(
    contents: &Mmap,
    fingerprint: Fingerprint,
    block_shift: u8,
    parallelism: Parallelism,
) -> (Vec<u8>, Layout) {
    hint::sequential(contents);
    let windows = scan::windows(contents, parallelism);
    let streamed = stream(contents, windows, fingerprint, block_shift, parallelism);
    hint::normal(contents);
    let bytes = streamed.expect("scanned starts and a valid block shift encode");
    let layout = Layout::parse(&bytes, fingerprint).expect("a freshly encoded header parses");
    (bytes, layout)
}

/// Date of the message at `start..end` of `contents`, an error when the range is not inside it.
fn message_date(contents: &[u8], start: usize, end: usize) -> io::Result<i64> {
    contents
        .get(start..end)
        .map(date::extract)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "a message starts past the end"))
}

/// Messages `layout` holds. Its header passed the length check, so on a 64-bit target the count
/// fits; a count past `usize::MAX` on a narrower target saturates, and the lookups past the
/// messages the file can hold fail verification and are answered by the rebuild.
fn messages(layout: &Layout) -> usize {
    narrow(layout.count).unwrap_or(usize::MAX)
}

/// Payload bytes of every block of `section`, read from the directory entries alone.
fn section_bytes(layout: &Layout, bytes: &[u8], section: Section) -> u64 {
    (0..layout.blocks())
        .filter_map(|block| {
            let (entry, _) = layout.entry_at(bytes, section, block)?;
            codec::payload_len(layout.block_len(block)?, entry.width)
        })
        .fold(0_u64, |total, payload| total.saturating_add(widen(payload)))
}

/// The index file for the messages whose starts `windows` yields in order, as bytes.
///
/// # Errors
///
/// An error when `block_shift` is outside `1..=16` or a start lies past the end of `contents`.
#[expect(
    clippy::too_many_arguments,
    reason = "five inputs against the bound of four: the writer's fingerprint and block shift, \
              the bytes and windows it dates, and the parallelism of that dating are independent, \
              and a struct bundling any two would exist for this private function alone"
)]
fn stream<I>(
    contents: &[u8],
    windows: I,
    fingerprint: Fingerprint,
    block_shift: u8,
    parallelism: Parallelism,
) -> io::Result<Vec<u8>>
where
    I: IntoIterator<Item = Vec<usize>>,
{
    let mut sink = io::Cursor::new(Vec::new());
    let writer = Writer::new(&mut sink, fingerprint, block_shift)?;
    let per_block = 1_usize
        .checked_shl(u32::from(block_shift))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "block shift is too large"))?;
    let mut streamer = Streamer {
        carry: None,
        contents,
        dates: Vec::new(),
        parallelism,
        per_block,
        starts: Vec::new(),
        writer,
    };
    for window in windows {
        streamer.feed(window)?;
    }
    streamer.finish()?;
    Ok(sink.into_inner())
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
    let last = Parsed::new(layout.entry_at(bytes, section, last_block)?);
    read(&Reach {
        bytes,
        first,
        last,
        same: first_block == last_block,
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

    use super::{Cell, Index, Parsed, Section, codec, format};
    use crate::error::MboxTurboError;
    use crate::fingerprint::Fingerprint;
    use crate::mailbox::map_read_only;
    use crate::scan::{self, Parallelism};
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
            let good = Index::build_with(Arc::clone(&mailbox), fingerprint, shift)
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
    fn a_message_without_a_date_is_dated_zero() {
        let index = Fixture::new().built();
        assert_eq!(index.date(7), Some(0), "message 7 has no Date header");
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
        let dates = vec![0_i64; starts.len()];
        let bytes = format::encode(
            &starts,
            &dates,
            fixture.fingerprint,
            format::DEFAULT_BLOCK_SHIFT,
        )
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
    fn dated_mailbox(messages: usize) -> Vec<u8> {
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
        let index = Index::build_with(mailbox, fingerprint, 5);
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

    /// `format::encode` over the whole scan, the reference the streaming build must match.
    fn reference(contents: &[u8], fingerprint: Fingerprint, shift: u8) -> Vec<u8> {
        let starts = scan::find_message_starts(contents);
        let dates: Vec<i64> = starts
            .iter()
            .enumerate()
            .map(|(position, &start)| {
                let end = starts
                    .get(position.saturating_add(1))
                    .copied()
                    .unwrap_or(contents.len());
                super::date::extract(&contents[start..end])
            })
            .collect();
        let wide: Vec<u64> = starts.iter().map(|&start| widen(start)).collect();
        format::encode(&wide, &dates, fingerprint, shift).expect("the reference encodes")
    }

    #[test]
    fn a_build_over_forced_small_windows_matches_the_whole_vector_encoding() {
        let contents = dated_mailbox(10_000);
        let fingerprint = Fingerprint::new(&contents, None);
        for (segment, per_window, shift) in [(4096, 1, 8), (999, 3, 8), (50_000, 2, 5), (1, 7, 1)] {
            let windows = scan::windows_with(&contents, segment, per_window, Parallelism::Parallel);
            let streamed = super::stream(
                &contents,
                windows,
                fingerprint,
                shift,
                Parallelism::Parallel,
            )
            .expect("the streaming build encodes");
            assert_eq!(
                streamed,
                reference(&contents, fingerprint, shift),
                "segment {segment} x {per_window} windows at shift {shift} equals the reference"
            );
        }
    }

    #[test]
    fn a_block_straddling_a_window_boundary_decodes_to_the_per_position_spans() {
        let contents = dated_mailbox(10_000);
        let fingerprint = Fingerprint::new(&contents, None);
        let windows = scan::windows_with(&contents, 3000, 1, Parallelism::Parallel);
        let bytes = super::stream(&contents, windows, fingerprint, 8, Parallelism::Parallel)
            .expect("the build encodes");
        let layout = format::Layout::parse(&bytes, fingerprint).expect("the header parses");
        let starts = scan::find_message_starts(&contents);
        for position in 0..starts.len() {
            let span = layout
                .span(&bytes, position)
                .expect("every position has a span");
            let end = starts
                .get(position.saturating_add(1))
                .copied()
                .unwrap_or(contents.len());
            assert_eq!(
                span,
                starts[position]..end,
                "position {position} decodes its span"
            );
        }
    }

    #[test]
    fn every_streamed_date_equals_the_extractor_including_the_last_message_of_each_window() {
        let contents = dated_mailbox(10_000);
        let fingerprint = Fingerprint::new(&contents, None);
        let windows: Vec<Vec<usize>> =
            scan::windows_with(&contents, 3000, 1, Parallelism::Parallel).collect();
        let bytes = super::stream(&contents, windows, fingerprint, 8, Parallelism::Parallel)
            .expect("the build encodes");
        let layout = format::Layout::parse(&bytes, fingerprint).expect("the header parses");
        let starts = scan::find_message_starts(&contents);
        for position in 0..starts.len() {
            let end = starts.get(position.saturating_add(1)).copied();
            let message = &contents[starts[position]..end.unwrap_or(contents.len())];
            assert_eq!(
                layout.date(&bytes, position),
                Some(super::date::extract(message)),
                "position {position} carries the extractor's date"
            );
        }
    }

    #[test]
    fn an_empty_mailbox_streams_to_the_reference_empty_index() {
        let fingerprint = Fingerprint::new(b"", None);
        let streamed = super::stream(
            b"",
            scan::windows(b"", Parallelism::Parallel),
            fingerprint,
            8,
            Parallelism::Parallel,
        )
        .expect("an empty mailbox encodes");
        assert_eq!(
            streamed,
            reference(b"", fingerprint, 8),
            "no messages yield the reference empty file"
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
            shift in prop_oneof![1_u8..=4, Just(format::DEFAULT_BLOCK_SHIFT)],
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
            shift in prop_oneof![1_u8..=4, Just(format::DEFAULT_BLOCK_SHIFT)],
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
