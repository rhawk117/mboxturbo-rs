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

use self::format::{Layout, Section};
use crate::error::{Corruption, MboxTurboError};
use crate::fingerprint::Fingerprint;
use crate::mailbox::map_read_only;
use crate::scan;
use crate::width::{narrow, widen};

/// First eight bytes of every index file.
const MAGIC: [u8; 8] = *b"MBOXTIDX";
/// Blocks tracked by one word of a verified bitmap.
const WORD_BITS: usize = 64;

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
    /// One bit per dates block, set once the block passed its checksum.
    dates_verified: Box<[AtomicU64]>,
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
    /// One bit per starts block, set once the block passed its checksum.
    starts_verified: Box<[AtomicU64]>,
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
    /// The block the starts belong to, or `None` while the slot holds nothing usable.
    block: Option<usize>,
    /// Where the block's last message ends: the next block's first start or the mailbox length.
    end: usize,
    /// The start of every message in the block, reused across refills.
    starts: Vec<usize>,
}

impl Slot {
    /// Byte range of the message `within` the block, or `None` when it would run backwards.
    fn span(&self, within: usize) -> Option<Range<usize>> {
        let start = *self.starts.get(within)?;
        let end = within
            .checked_add(1)
            .and_then(|next| self.starts.get(next))
            .map_or(self.end, |&next| next);
        (start <= end).then_some(start..end)
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
    /// The span of `position` from the cached blocks, `None` when they cannot answer it.
    fn cached(&mut self, position: usize) -> Option<Range<usize>> {
        if self.index.replacement.get().is_some() {
            return None;
        }
        let shift = u32::from(self.index.layout.block_shift);
        let block = position.checked_shr(shift)?;
        let within = position.checked_sub(block.checked_shl(shift)?)?;
        self.promote(block)?;
        let span = self.slots.0.span(within)?;
        (span.end <= self.index.mailbox.len()).then_some(span)
    }

    /// Makes `block` the newest slot, decoding it unless one of the slots holds it.
    fn promote(&mut self, block: usize) -> Option<()> {
        if self.slots.0.block == Some(block) {
            return Some(());
        }
        mem::swap(&mut self.slots.0, &mut self.slots.1);
        if self.slots.0.block == Some(block) {
            return Some(());
        }
        self.slots.0.block = None;
        self.slots.0.end = self.index.decode(block, &mut self.slots.0.starts)?;
        self.slots.0.block = Some(block);
        Some(())
    }

    /// Byte range of the message at `position`, answering exactly what [`Index::span`] does.
    pub(crate) fn span(&mut self, position: usize) -> Option<Range<usize>> {
        self.cached(position).or_else(|| self.index.span(position))
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

    /// Indexes every message in `contents`, scanning it and reading each Date header on all
    /// rayon threads.
    ///
    /// A message starts at a line beginning with `From `, matching Python's `mailbox.mbox`; a
    /// message without a parsable Date header is dated zero.
    #[must_use]
    pub fn build(contents: Arc<Mmap>, fingerprint: Fingerprint) -> Self {
        let (bytes, layout) = encoded(&contents, fingerprint);
        Self::new(contents, Backing::Owned(bytes), layout, None)
    }

    /// A cursor that walks the spans of consecutive positions one block at a time.
    pub(crate) const fn cursor(&self) -> Cursor<'_> {
        Cursor {
            index: self,
            slots: (
                Slot {
                    block: None,
                    end: 0,
                    starts: Vec::new(),
                },
                Slot {
                    block: None,
                    end: 0,
                    starts: Vec::new(),
                },
            ),
        }
    }

    /// Date of the message at `position` in unix seconds, `Some(0)` when it has no parsable
    /// Date header, or `None` past the last message.
    #[must_use]
    pub fn date(&self, position: usize) -> Option<i64> {
        let needed = position..position.saturating_add(1);
        self.lookup(Section::Dates, needed, |bytes, layout| {
            layout.date(bytes, position)
        })
    }

    /// Decodes the starts of original `block` into `starts` after verifying it and the block
    /// that follows, and returns where the block's last message ends. `None` when the block or
    /// its successor is damaged or places a message outside the mapping.
    fn decode(&self, block: usize, starts: &mut Vec<usize>) -> Option<usize> {
        #[cfg(test)]
        #[expect(unused_results, reason = "the previous count is not needed")]
        self.decoded.fetch_add(1, Ordering::Relaxed);
        let first = block.checked_shl(u32::from(self.layout.block_shift))?;
        if !self.verify(Section::Starts, first) {
            return None;
        }
        let (entry, payload) = self
            .layout
            .entry(self.original.bytes(), Section::Starts, block)?;
        starts.clear();
        for within in 0..self.layout.block_len(block)? {
            starts.push(narrow(codec::start(&entry, payload, within)?)?);
        }
        self.end_of(block)
    }

    /// Starts blocks decoded by cursors so far.
    #[cfg(test)]
    pub(crate) fn decoded_blocks(&self) -> usize {
        self.decoded.load(Ordering::Relaxed)
    }

    /// The first start of the block after `block`, or the mailbox length after the last block.
    fn end_of(&self, block: usize) -> Option<usize> {
        let next = block.checked_add(1)?;
        if next >= self.layout.blocks() {
            return narrow(self.layout.fingerprint.len());
        }
        let first = next.checked_shl(u32::from(self.layout.block_shift))?;
        if !self.verify(Section::Starts, first) {
            return None;
        }
        narrow(self.layout.start(self.original.bytes(), first)?)
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
    fn lookup<T, F>(&self, section: Section, needed: Range<usize>, read: F) -> Option<T>
    where
        F: Fn(&[u8], &Layout) -> Option<T>,
    {
        if let Some((bytes, layout)) = self.replacement.get() {
            return read(bytes, layout);
        }
        let count = messages(&self.layout);
        if needed.start >= count {
            return None;
        }
        let mut positions = needed.start..needed.end.min(count);
        let sound = positions.all(|position| self.verify(section, position));
        let found = if sound {
            read(self.original.bytes(), &self.layout)
        } else {
            None
        };
        found.or_else(|| {
            let (bytes, layout) = self.rebuilt();
            read(bytes, layout)
        })
    }

    /// An index over `original`, whose header is `layout`, with no block verified yet.
    fn new(mailbox: Arc<Mmap>, original: Backing, layout: Layout, origin: Option<PathBuf>) -> Self {
        Self {
            #[cfg(test)]
            decoded: AtomicUsize::new(0),
            dates_verified: bitmap(layout.blocks()),
            fingerprint: layout.fingerprint,
            layout,
            mailbox,
            origin,
            original,
            replacement: OnceLock::new(),
            rewrite: OnceLock::new(),
            starts_verified: bitmap(layout.blocks()),
        }
    }

    /// Rescans the mailbox and, when the index was loaded from a file, rewrites that file with
    /// the result and keeps the outcome for [`Index::rewrite_outcome`].
    fn rebuild(&self) -> (Vec<u8>, Layout) {
        let (bytes, layout) = encoded(&self.mailbox, self.fingerprint);
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
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "read by the Python bindings once T9 lands")
    )]
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
    pub fn span(&self, position: usize) -> Option<Range<usize>> {
        let end = self.mailbox.len();
        let needed = position..position.saturating_add(2);
        self.lookup(Section::Starts, needed, |bytes, layout| {
            layout.span(bytes, position).filter(|span| span.end <= end)
        })
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

    /// The verified bitmap of `section`.
    fn verified_bits(&self, section: Section) -> &[AtomicU64] {
        match section {
            Section::Dates => &self.dates_verified,
            Section::Starts => &self.starts_verified,
        }
    }

    /// Blocks of `section` whose checksum a lookup has checked and accepted.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "read by the cache statistics once T11 lands")
    )]
    pub(crate) fn verified_blocks(&self, section: Section) -> usize {
        let bits = self.verified_bits(section);
        (0..self.layout.blocks())
            .filter(|&block| is_set(bits, block))
            .count()
    }

    /// Whether the original `section` block holding `position` passes its checksum, checking it
    /// only the first time. An entry the layout refuses fails.
    fn verify(&self, section: Section, position: usize) -> bool {
        let bits = self.verified_bits(section);
        let Some(block) = position.checked_shr(u32::from(self.layout.block_shift)) else {
            return false;
        };
        if is_set(bits, block) {
            return true;
        }
        let sound = self
            .layout
            .entry(self.original.bytes(), section, block)
            .is_some_and(|(entry, payload)| codec::verify(&entry, payload));
        if sound {
            set(bits, block);
        }
        sound
    }
}

/// A bitmap of `blocks` clear bits.
fn bitmap(blocks: usize) -> Box<[AtomicU64]> {
    iter::repeat_with(|| AtomicU64::new(0))
        .take(blocks.div_ceil(WORD_BITS))
        .collect()
}

/// The word of `bits` holding `block`'s bit and the mask selecting it, or `None` past the end.
fn bit(bits: &[AtomicU64], block: usize) -> Option<(&AtomicU64, u64)> {
    let word = bits.get(block.checked_div(WORD_BITS)?)?;
    #[expect(
        clippy::disallowed_methods,
        reason = "a remainder of division by 64 always fits u32, so the conversion never fails"
    )]
    let place = u32::try_from(block.checked_rem(WORD_BITS)?).ok()?;
    Some((word, 1_u64.checked_shl(place)?))
}

/// Dates in unix seconds of the messages starting at `starts`, zero for a message without a
/// parsable Date header.
fn dates(contents: &[u8], starts: &[usize]) -> Vec<i64> {
    starts
        .par_iter()
        .enumerate()
        .map(|(position, &start)| {
            let end = position
                .checked_add(1)
                .and_then(|next| starts.get(next))
                .map_or(contents.len(), |&next| next);
            // The scanner emits ascending starts below `contents.len()`, so the range exists.
            contents.get(start..end).map_or(0, date::extract)
        })
        .collect()
}

/// The index file for `contents` at the default block shift, with its header.
#[expect(
    clippy::expect_used,
    reason = "the starts and dates have equal lengths and are cut into full blocks by \
              format::encode itself, which is all it refuses, and a file it wrote for \
              `fingerprint` has a header that parses for `fingerprint`"
)]
fn encoded(contents: &[u8], fingerprint: Fingerprint) -> (Vec<u8>, Layout) {
    let starts = scan::find_message_starts(contents);
    let dates = dates(contents, &starts);
    let wide: Vec<u64> = starts.iter().map(|&start| widen(start)).collect();
    let bytes = format::encode(&wide, &dates, fingerprint, format::DEFAULT_BLOCK_SHIFT)
        .expect("starts and dates of equal length encode");
    let layout = Layout::parse(&bytes, fingerprint).expect("a freshly encoded header parses");
    (bytes, layout)
}

/// Whether `block`'s bit is set in `bits`.
fn is_set(bits: &[AtomicU64], block: usize) -> bool {
    bit(bits, block).is_some_and(|(word, mask)| word.load(Ordering::Relaxed) & mask != 0)
}

/// Messages `layout` holds. Its header passed the length check, so on a 64-bit target the count
/// fits; a count past `usize::MAX` on a narrower target saturates, and the lookups past the
/// messages the file can hold fail verification and are answered by the rebuild.
fn messages(layout: &Layout) -> usize {
    narrow(layout.count).unwrap_or(usize::MAX)
}

/// Sets `block`'s bit in `bits`. Relaxed suffices: the bytes behind it never change, and the
/// bit only spares a recheck.
fn set(bits: &[AtomicU64], block: usize) {
    if let Some((word, mask)) = bit(bits, block) {
        #[expect(unused_results, reason = "the previous bits are not needed")]
        word.fetch_or(mask, Ordering::Relaxed);
    }
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
    use tempfile::TempDir;

    use super::{Index, Section, format};
    use crate::error::MboxTurboError;
    use crate::fingerprint::Fingerprint;
    use crate::mailbox::map_read_only;
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
}
