//! The v2 index file: a fixed header, interleaved block payloads and two block directories.
//!
//! Everything is little-endian. A file is, in order:
//!
//! 1. The 72-byte header.
//!
//!    | bytes   | field                                                        |
//!    | ------- | ------------------------------------------------------------ |
//!    | 0..8    | magic `MBOXTIDX`                                             |
//!    | 8..12   | version, `u32`, 3                                            |
//!    | 12      | block shift, `u8`, 1 to 16: a block holds `2^shift` messages |
//!    | 13      | flags, `u8`, 0                                               |
//!    | 14..16  | reserved, `u16`                                              |
//!    | 16..24  | fingerprint length, `u64`                                    |
//!    | 24..40  | fingerprint modification time in nanoseconds, `i128`         |
//!    | 40..48  | fingerprint sample hash, `u64`                               |
//!    | 48..56  | message count, `u64`                                         |
//!    | 56..64  | directory offset from the file start, `u64`                  |
//!    | 64..72  | `xxh3_64` of bytes 0..64, `u64`                              |
//!
//! 2. The block payloads in push order: for block `b`, its starts payload and then its dates
//!    payload, each packed by [`codec`].
//! 3. The starts directory and then the dates directory at the directory offset. Each holds
//!    `ceil(count / 2^shift)` entries of 32 bytes.
//!
//!    | bytes   | field                                                 |
//!    | ------- | ----------------------------------------------------- |
//!    | 0..8    | block base, `u64`                                     |
//!    | 8..16   | payload offset from the file start, `u64`             |
//!    | 16..24  | checksum over base, width, flags and payload, `u64`   |
//!    | 24      | width in bits per code, `u8`                          |
//!    | 25      | flags, `u8`                                           |
//!    | 26..32  | reserved                                              |
//!
//! The file ends exactly at the directory offset plus both directories. Opening checks the
//! header and that length arithmetic only; an entry and its payload are checked when a lookup
//! reaches them, and a lookup that finds them inconsistent answers `None`.
//!
//! The span of message `n` runs from its start to the next message's start, or to the
//! fingerprint length (the mailbox end) for the last message.

#[cfg(test)]
use std::io::Cursor;
use std::io::{self, Seek, Write};
use std::ops::Range;

use xxhash_rust::xxh3::xxh3_64;

use super::{BlockSize, MAGIC, Rejection, codec};
use crate::error::Corruption;
use crate::fingerprint::Fingerprint;
use crate::width::{narrow, widen};

/// Bytes of the header covered by its checksum.
const CHECKED_LEN: usize = 64;
/// Bytes in one directory entry.
pub(crate) const ENTRY_LEN: usize = 32;
/// Bytes before the first block payload.
pub(crate) const HEADER_LEN: usize = 72;
/// Format version this build writes and reads; older files count as stale, newer as corrupt.
pub(crate) const VERSION: u32 = 3;

/// A directory entry and where its payload sits.
#[derive(Debug, Clone, Copy)]
struct Entry {
    /// The decoded entry.
    block: codec::Block,
    /// Payload offset from the file start.
    offset: u64,
}

/// The header of an opened file: enough to find any block without reading the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Layout {
    /// Each block holds this many messages, except possibly the last.
    pub block_size: BlockSize,
    /// Number of messages.
    pub count: usize,
    /// Where the starts directory begins, from the file start.
    pub dir_offset: u64,
    /// Identity of the mailbox the index was built from.
    pub fingerprint: Fingerprint,
}

/// Which of the two block directories an entry belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Section {
    /// Message dates in unix seconds.
    Dates,
    /// Message start offsets.
    Starts,
}

/// Builds an index file a block at a time, keeping only the directory entries in memory.
#[derive(Debug)]
pub(crate) struct Writer<W: Write + Seek> {
    /// Each full block holds this many messages.
    block_size: BlockSize,
    /// Whether a block shorter than a full one was pushed, which must be the last.
    closed: bool,
    /// Messages pushed so far.
    count: usize,
    /// Dates directory entries, one per block.
    dates: Vec<Entry>,
    /// Identity of the mailbox being indexed.
    fingerprint: Fingerprint,
    /// Bytes written so far, which is where the next payload goes.
    offset: u64,
    /// Where the file goes; the writer owns its position.
    sink: W,
    /// Starts directory entries, one per block.
    starts: Vec<Entry>,
}

impl Entry {
    /// The 32 bytes of the directory entry.
    fn bytes(&self) -> Vec<u8> {
        let mut raw = Vec::with_capacity(ENTRY_LEN);
        raw.extend_from_slice(&self.block.base.to_le_bytes());
        raw.extend_from_slice(&self.offset.to_le_bytes());
        raw.extend_from_slice(&self.block.checksum.to_le_bytes());
        raw.extend_from_slice(&[self.block.width, self.block.flags, 0, 0, 0, 0, 0, 0]);
        raw
    }
}

impl Layout {
    /// Messages in block `block`, or `None` when the block does not exist.
    pub(crate) fn block_len(&self, block: usize) -> Option<usize> {
        let per_block = self.block_size.entries();
        let first = block.checked_mul(per_block)?;
        let held = self.count.checked_sub(first)?.min(per_block);
        (held > 0).then_some(held)
    }

    /// Number of blocks in each directory.
    pub(crate) const fn blocks(&self) -> usize {
        self.count.div_ceil(self.block_size.entries())
    }

    /// The range `start..end` when it runs forward and ends no later than the `mailbox` length,
    /// else `None`: a span the index claims must lie inside the mailbox it describes.
    #[inline]
    pub(crate) fn bounded(start: usize, end: usize, mailbox: usize) -> Option<Range<usize>> {
        (start <= end && end <= mailbox).then_some(start..end)
    }

    /// Checks that the directory offset and block count put the end of the directories exactly
    /// at `actual`, the length of the file.
    fn check_extent(&self, actual: usize) -> Result<(), Corruption> {
        if self.dir_offset < widen(HEADER_LEN) {
            return Err(Corruption::Bounds {
                position: 0,
                offset: self.dir_offset,
            });
        }
        let declared = end_of_directories(widen(self.count), self.per_block(), self.dir_offset)
            .unwrap_or(u64::MAX);
        if declared == widen(actual) {
            Ok(())
        } else {
            Err(Corruption::Length {
                declared,
                actual: widen(actual),
            })
        }
    }

    /// Date of message `position` in unix seconds, `Some(None)` when it has none, or `None` when
    /// it does not exist or its block is unreadable.
    #[cfg(test)]
    #[expect(
        clippy::option_option,
        reason = "the outer `None` is a refused block, the inner one a message with no date"
    )]
    pub(crate) fn date(&self, bytes: &[u8], position: usize) -> Option<Option<i64>> {
        let (block, within) = self.held(position)?;
        let (entry, payload) = self.entry(bytes, Section::Dates, block)?;
        codec::date(&entry, payload, within)
    }

    /// The directory entry of `block` in `section` and its payload, or `None` when the block does
    /// not exist, the entry lies outside `bytes`, or the payload does not fit before the
    /// directories. The checksum is not checked here.
    #[cfg(test)]
    pub(crate) fn entry<'bytes>(
        &self,
        bytes: &'bytes [u8],
        section: Section,
        block: usize,
    ) -> Option<(codec::Block, &'bytes [u8])> {
        let (entry, payload) = self.entry_at(bytes, section, block)?;
        Some((entry, bytes.get(payload)?))
    }

    /// The directory entry of `block` in `section` and its payload as a byte range in `bytes`,
    /// which lies between the header and the directories but is not checked against the length
    /// of `bytes`. `None` when the block does not exist or the entry lies outside `bytes`.
    pub(crate) fn entry_at(
        &self,
        bytes: &[u8],
        section: Section,
        block: usize,
    ) -> Option<(codec::Block, Range<usize>)> {
        let at = self.entry_offset(section, block)?;
        let raw = bytes.get(at..at.checked_add(ENTRY_LEN)?)?;
        let entry = codec::Block {
            base: read_u64(raw, 0)?,
            checksum: read_u64(raw, 16)?,
            flags: *raw.get(25)?,
            width: *raw.get(24)?,
        };
        let payload = self.payload_range(narrow(read_u64(raw, 8)?)?, block, entry.width)?;
        Some((entry, payload))
    }

    /// Byte offset of the entry of `block` in `section`.
    fn entry_offset(&self, section: Section, block: usize) -> Option<usize> {
        let skipped = match section {
            Section::Dates => self.blocks(),
            Section::Starts => 0,
        };
        let entries = skipped.checked_add(block)?;
        narrow(self.dir_offset)?.checked_add(entries.checked_mul(ENTRY_LEN)?)
    }

    /// As [`Layout::place`], `None` when message `position` does not exist.
    #[cfg(test)]
    fn held(&self, position: usize) -> Option<(usize, usize)> {
        let (block, within) = self.place(position)?;
        (within < self.block_len(block)?).then_some((block, within))
    }

    /// Whether `position` is the last message, whose end is the mailbox end and not a
    /// successor's start.
    #[inline]
    pub(crate) fn is_last(&self, position: usize) -> bool {
        position
            .checked_add(1)
            .is_some_and(|following| following == self.count)
    }

    /// The highest position block `block` holds, or `None` when the block does not exist.
    pub(crate) fn last_in_block(&self, block: usize) -> Option<usize> {
        let first = block.checked_shl(u32::from(self.block_size.shift()))?;
        first.checked_add(self.block_len(block)?.checked_sub(1)?)
    }

    /// Reads and checks the header of `bytes`, and that its length matches the header.
    ///
    /// Nothing past the header is read, and nothing is allocated, so a header that claims
    /// an absurd count is rejected by arithmetic on the claimed values alone.
    pub(crate) fn parse(bytes: &[u8], expected: Fingerprint) -> Result<Self, Rejection> {
        let head = bytes
            .get(..HEADER_LEN)
            .ok_or_else(|| short_header(bytes.len()))?;
        check_signature_and_version(head)?;
        check_header_checksum(head)?;
        let layout = decode_header(head, bytes.len())?;
        if layout.fingerprint != expected {
            return Err(Rejection::Stale);
        }
        layout.check_extent(bytes.len())?;
        Ok(layout)
    }

    /// The range of `block`'s payload when it starts at `first`, holds `width`-bit codes and
    /// lies between the header and the directories.
    fn payload_range(&self, first: usize, block: usize, width: u8) -> Option<Range<usize>> {
        let last = first.checked_add(codec::payload_len(self.block_len(block)?, width)?)?;
        (first >= HEADER_LEN && last <= narrow(self.dir_offset)?).then_some(first..last)
    }

    /// Messages in a full block.
    const fn per_block(&self) -> u64 {
        self.block_size.messages()
    }

    /// The block holding `position` and the place of `position` within it, by the block shift.
    ///
    /// Arithmetic alone: it does not check that the message exists, which the caller proved or
    /// [`Layout::block_len`] answers.
    #[inline]
    pub(crate) fn place(&self, position: usize) -> Option<(usize, usize)> {
        let shift = u32::from(self.block_size.shift());
        Some((
            position.checked_shr(shift)?,
            position & !usize::MAX.checked_shl(shift)?,
        ))
    }

    /// Byte range of message `position`: its start to the next start, or to the mailbox end for
    /// the last message. `None` past the end, for an unreadable block of the message or of its
    /// successor, or for a range that would run backwards or past the mailbox.
    #[cfg(test)]
    pub(crate) fn span(&self, bytes: &[u8], position: usize) -> Option<Range<usize>> {
        let start = narrow(self.start(bytes, position)?)?;
        let mailbox = narrow(self.fingerprint.len())?;
        let end = if self.is_last(position) {
            mailbox
        } else {
            narrow(self.start(bytes, position.checked_add(1)?)?)?
        };
        Self::bounded(start, end, mailbox)
    }

    /// Start offset of message `position`, or `None` when it does not exist or its block cannot
    /// be read.
    #[cfg(test)]
    pub(crate) fn start(&self, bytes: &[u8], position: usize) -> Option<u64> {
        let (block, within) = self.held(position)?;
        let (entry, payload) = self.entry(bytes, Section::Starts, block)?;
        codec::start(&entry, payload, within)
    }
}

impl<W: Write + Seek> Writer<W> {
    /// Checks that a block of `starts` and `dates` values may follow the blocks pushed so far,
    /// and closes the file to further blocks when it is short.
    fn admit(&mut self, starts: usize, dates: usize) -> io::Result<()> {
        let full = self.block_size.entries();
        if starts != dates {
            return Err(invalid("starts and dates differ in length"));
        }
        if self.closed || starts == 0 || starts > full {
            return Err(invalid("a block must be full unless it is the last"));
        }
        self.closed = starts != full;
        Ok(())
    }

    /// Counts a block of `messages` and `written` payload bytes; returns where the block began.
    fn advance(&mut self, written: u64, messages: usize) -> io::Result<u64> {
        let began = self.offset;
        self.offset = began
            .checked_add(written)
            .ok_or_else(|| invalid("index exceeds the addressable size"))?;
        self.count = self.count.saturating_add(messages);
        Ok(began)
    }

    /// Writes both directories and the final header, flushes, and returns the message count.
    pub(crate) fn finish(mut self) -> io::Result<usize> {
        let dir_offset = self.offset;
        for entry in self.starts.iter().chain(&self.dates) {
            self.sink.write_all(&entry.bytes())?;
        }
        self.sink.rewind()?;
        self.sink
            .write_all(&sealed_header(&self.layout(dir_offset)))?;
        self.sink.flush()?;
        Ok(self.count)
    }

    /// The header fields for a directory at `dir_offset`.
    const fn layout(&self, dir_offset: u64) -> Layout {
        Layout {
            block_size: self.block_size,
            count: self.count,
            dir_offset,
            fingerprint: self.fingerprint,
        }
    }

    /// Starts a file at the front of `sink` with a provisional header whose zero checksum makes
    /// an unfinished file read as corrupt.
    pub(crate) fn new(
        mut sink: W,
        fingerprint: Fingerprint,
        block_size: BlockSize,
    ) -> io::Result<Self> {
        sink.rewind()?;
        let mut writer = Self {
            block_size,
            closed: false,
            count: 0,
            dates: Vec::new(),
            fingerprint,
            offset: widen(HEADER_LEN),
            sink,
            starts: Vec::new(),
        };
        let head = provisional_header(&writer.layout(0));
        writer.sink.write_all(&head)?;
        Ok(writer)
    }

    /// Appends one block: every block but the last holds exactly `block_size.entries()` values.
    pub(crate) fn push(&mut self, starts: &[u64], dates: &[Option<i64>]) -> io::Result<()> {
        self.admit(starts.len(), dates.len())?;
        let mut payload = Vec::new();
        let starts_block = codec::encode_starts(starts, &mut payload);
        let starts_len = widen(payload.len());
        let Some(dates_block) = codec::encode_dates(dates, &mut payload) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "the dates of the block starting at message {} span the whole i64 range, \
                     leaving no code to mark a missing date",
                    self.count
                ),
            ));
        };
        self.sink.write_all(&payload)?;
        let began = self.advance(widen(payload.len()), starts.len())?;
        self.starts.push(Entry {
            block: starts_block,
            offset: began,
        });
        self.dates.push(Entry {
            block: dates_block,
            offset: began.saturating_add(starts_len),
        });
        Ok(())
    }
}

/// Checks the header checksum over its first 64 bytes.
fn check_header_checksum(head: &[u8]) -> Result<(), Corruption> {
    let covered = head
        .get(..CHECKED_LEN)
        .ok_or_else(|| short_header(head.len()))?;
    let stored = read_u64(head, CHECKED_LEN).ok_or_else(|| short_header(head.len()))?;
    if xxh3_64(covered) == stored {
        Ok(())
    } else {
        Err(Corruption::Checksum)
    }
}

/// Checks the magic and version; an older version is stale, a newer one corrupt.
fn check_signature_and_version(head: &[u8]) -> Result<(), Rejection> {
    if head.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
        return Err(Corruption::Signature.into());
    }
    let version = read::<4>(head, MAGIC.len())
        .map(u32::from_le_bytes)
        .ok_or_else(|| short_header(head.len()))?;
    if version < VERSION {
        return Err(Rejection::Stale);
    }
    if version != VERSION {
        return Err(Corruption::Version(version).into());
    }
    Ok(())
}

/// Where the file ends if a header claiming `count` messages is true, or `None` on overflow.
fn end_of_directories(count: u64, per_block: u64, dir_offset: u64) -> Option<u64> {
    let entries = count.div_ceil(per_block).checked_mul(2)?;
    let bytes = entries.checked_mul(widen(ENTRY_LEN))?;
    dir_offset.checked_add(bytes)
}

/// The header's `count` as a `usize`, or the length refusal for a count this target cannot hold,
/// which no file of `actual` bytes can match.
fn narrow_count(
    count: u64,
    block_size: BlockSize,
    dir_offset: u64,
    actual: usize,
) -> Result<usize, Corruption> {
    narrow(count).ok_or_else(|| Corruption::Length {
        declared: end_of_directories(count, block_size.messages(), dir_offset).unwrap_or(u64::MAX),
        actual: widen(actual),
    })
}

/// Reads the layout fields out of a header whose checksum already held, refusing a block shift
/// outside the range the format allows and a count that does not fit `usize`; `actual` is the
/// file length.
fn decode_header(head: &[u8], actual: usize) -> Result<Layout, Rejection> {
    let missing = || short_header(head.len());
    let raw = *head.get(12).ok_or_else(missing)?;
    let block_size = BlockSize::from_shift(raw).ok_or(Corruption::BlockShift(raw))?;
    let nanos = read::<16>(head, 24)
        .map(i128::from_le_bytes)
        .ok_or_else(missing)?;
    let field = |at| read_u64(head, at).ok_or_else(missing);
    let dir_offset = field(56)?;
    Ok(Layout {
        block_size,
        count: narrow_count(field(48)?, block_size, dir_offset, actual)?,
        dir_offset,
        fingerprint: Fingerprint::from_parts(field(16)?, nanos, field(40)?),
    })
}

/// The index file for `starts` and `dates` as bytes, split into blocks of `block_size.entries()`.
#[cfg(test)]
pub(crate) fn encode(
    starts: &[u64],
    dates: &[Option<i64>],
    fingerprint: Fingerprint,
    block_size: BlockSize,
) -> io::Result<Vec<u8>> {
    let per_block = block_size.entries();
    let mut sink = Cursor::new(Vec::new());
    let mut writer = Writer::new(&mut sink, fingerprint, block_size)?;
    for (block_starts, block_dates) in starts.chunks(per_block).zip(dates.chunks(per_block)) {
        writer.push(block_starts, block_dates)?;
    }
    if writer.finish()? != starts.len() || starts.len() != dates.len() {
        return Err(invalid("starts and dates differ in length"));
    }
    Ok(sink.into_inner())
}

/// The first 64 header bytes, which the checksum covers.
fn header_body(layout: &Layout) -> Vec<u8> {
    let mut head = Vec::with_capacity(HEADER_LEN);
    head.extend_from_slice(&MAGIC);
    head.extend_from_slice(&VERSION.to_le_bytes());
    head.extend_from_slice(&[layout.block_size.shift(), 0, 0, 0]);
    head.extend_from_slice(&layout.fingerprint.len().to_le_bytes());
    head.extend_from_slice(&layout.fingerprint.modified_nanos().to_le_bytes());
    head.extend_from_slice(&layout.fingerprint.sample_hash().to_le_bytes());
    head.extend_from_slice(&widen(layout.count).to_le_bytes());
    head.extend_from_slice(&layout.dir_offset.to_le_bytes());
    head
}

/// An invalid-input error carrying `reason`.
fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}

/// The header with a zero checksum, so a file that was never finished fails its checksum.
fn provisional_header(layout: &Layout) -> Vec<u8> {
    let mut head = header_body(layout);
    head.extend_from_slice(&0_u64.to_le_bytes());
    head
}

/// `N` bytes of `bytes` from offset `at`, or `None` when they are not all there.
fn read<const N: usize>(bytes: &[u8], at: usize) -> Option<[u8; N]> {
    bytes.get(at..)?.first_chunk::<N>().copied()
}

/// The `u64` at offset `at`.
fn read_u64(bytes: &[u8], at: usize) -> Option<u64> {
    read::<8>(bytes, at).map(u64::from_le_bytes)
}

/// The header with its checksum.
fn sealed_header(layout: &Layout) -> Vec<u8> {
    let mut head = header_body(layout);
    let checksum = xxh3_64(&head);
    head.extend_from_slice(&checksum.to_le_bytes());
    head
}

/// The error for a header missing bytes it must hold, in a file of `actual` bytes.
fn short_header(actual: usize) -> Corruption {
    Corruption::Length {
        declared: widen(HEADER_LEN),
        actual: widen(actual),
    }
}

#[cfg(test)]
mod tests {
    use proptest::collection::vec;
    use proptest::prelude::*;

    use super::*;
    use crate::scan;

    /// `left + right` for test positions that cannot overflow.
    fn plus(left: usize, right: usize) -> usize {
        left.checked_add(right).expect("test offsets are small")
    }

    /// Mailbox identity used by the hand-built files.
    const fn print() -> Fingerprint {
        Fingerprint::from_parts(900_000, 7, 9)
    }

    /// Starts for `count` messages inside the hand-built mailbox.
    fn starts_of(count: u64) -> Vec<u64> {
        (0..count)
            .map(|position| {
                position
                    .saturating_mul(37)
                    .saturating_add(position.rem_euclid(5))
            })
            .collect()
    }

    /// Dates for `count` messages, with every ninth missing.
    fn dates_of(count: u64) -> Vec<Option<i64>> {
        (0..count)
            .map(|position| {
                (position.rem_euclid(9) != 0).then(|| {
                    let minutes = i64::try_from(position).expect("test positions fit i64");
                    minutes.saturating_mul(60).saturating_add(1_400_000_000)
                })
            })
            .collect()
    }

    /// An encoded file of `count` messages at `shift`.
    fn file(count: u64, shift: u8) -> Vec<u8> {
        let block_size = size(shift);
        encode(&starts_of(count), &dates_of(count), print(), block_size)
            .expect("the writer encodes")
    }

    /// The layout of `bytes`, which must parse.
    fn open(bytes: &[u8]) -> Layout {
        Layout::parse(bytes, print()).expect("the header is valid")
    }

    /// The rejection from parsing `bytes`.
    fn rejection(bytes: &[u8]) -> Rejection {
        Layout::parse(bytes, print()).expect_err("the header is invalid")
    }

    /// The block size of `shift`, which must be within the range.
    fn size(shift: u8) -> BlockSize {
        BlockSize::from_shift(shift).expect("the shift is within the range")
    }

    /// A sealed header for a layout with these fields, whose shift byte may lie outside the range
    /// a `BlockSize` holds.
    fn sealed(count: usize, block_shift: u8, dir_offset: u64) -> Vec<u8> {
        let mut head = header_body(&Layout {
            block_size: BlockSize::default(),
            count,
            dir_offset,
            fingerprint: print(),
        });
        head[12] = block_shift;
        let checksum = xxh3_64(&head);
        head.extend_from_slice(&checksum.to_le_bytes());
        head
    }

    /// `bytes` with `value` stored at `at`.
    fn patched(mut bytes: Vec<u8>, at: usize, value: &[u8]) -> Vec<u8> {
        bytes[at..plus(at, value.len())].copy_from_slice(value);
        bytes
    }

    /// Where the first starts directory entry of `bytes` begins.
    fn first_entry(bytes: &[u8]) -> usize {
        narrow(open(bytes).dir_offset).expect("the offset fits")
    }

    #[test]
    fn every_start_and_date_reads_back() {
        let bytes = file(600, 8);
        let opened = open(&bytes);
        let starts = starts_of(600);
        let dates = dates_of(600);
        for (position, (start, date)) in starts.iter().zip(&dates).enumerate() {
            assert_eq!(
                opened.start(&bytes, position),
                Some(*start),
                "start {position}"
            );
            assert_eq!(
                opened.date(&bytes, position),
                Some(*date),
                "date {position}"
            );
        }
        assert_eq!(opened.start(&bytes, 600), None, "no message past the count");
    }

    #[test]
    fn an_empty_index_opens_with_no_blocks() {
        let bytes = file(0, 8);
        let opened = open(&bytes);
        assert_eq!(
            (opened.blocks(), opened.span(&bytes, 0)),
            (0, None),
            "nothing to serve"
        );
    }

    #[test]
    fn opening_ignores_a_corrupted_second_block() {
        let clean = file(600, 8);
        let entry_at = plus(first_entry(&clean), ENTRY_LEN);
        let damaged = patched(clean, entry_at, &[0xFF; 16]);
        let reopened = Layout::parse(&damaged, print()).expect("only the header is read on open");
        assert_eq!(reopened.start(&damaged, 0), Some(0), "block 0 still serves");
        assert_eq!(
            reopened.start(&damaged, 256),
            None,
            "the damaged block answers none"
        );
    }

    #[test]
    fn a_claim_of_two_to_the_sixty_messages_is_rejected_by_arithmetic() {
        let head = sealed(1 << 60, 1, 72);
        assert!(
            matches!(
                rejection(&head),
                Rejection::Corrupt(Corruption::Length { .. })
            ),
            "the directory size exceeds the file without allocating"
        );
    }

    #[test]
    fn a_version_one_file_is_stale() {
        let bytes = patched(file(10, 8), 8, &1_u32.to_le_bytes());
        assert!(
            matches!(rejection(&bytes), Rejection::Stale),
            "older versions rebuild"
        );
    }

    #[test]
    fn a_version_two_file_is_stale() {
        let bytes = patched(file(10, 8), 8, &2_u32.to_le_bytes());
        assert!(
            matches!(rejection(&bytes), Rejection::Stale),
            "a version-2 file may store a missing date as its block minimum, so it rebuilds"
        );
    }

    #[test]
    fn a_newer_version_is_corrupt() {
        let bytes = patched(file(10, 8), 8, &4_u32.to_le_bytes());
        assert!(
            matches!(
                rejection(&bytes),
                Rejection::Corrupt(Corruption::Version(4))
            ),
            "a newer version is not understood"
        );
    }

    #[test]
    fn a_different_fingerprint_is_stale() {
        let bytes = file(10, 8);
        let other = Fingerprint::from_parts(1, 7, 9);
        assert!(
            matches!(Layout::parse(&bytes, other), Err(Rejection::Stale)),
            "a changed mailbox invalidates the index"
        );
    }

    #[test]
    fn a_wrong_magic_is_corrupt() {
        let bytes = patched(file(10, 8), 0, b"X");
        assert!(
            matches!(rejection(&bytes), Rejection::Corrupt(Corruption::Signature)),
            "the magic must match"
        );
    }

    #[test]
    fn a_truncated_header_is_corrupt() {
        let bytes = file(10, 8);
        assert!(
            matches!(
                rejection(&bytes[..HEADER_LEN - 1]),
                Rejection::Corrupt(Corruption::Length { .. })
            ),
            "the header is 72 bytes"
        );
    }

    #[test]
    fn a_truncated_directory_is_corrupt() {
        let bytes = file(600, 8);
        assert!(
            matches!(
                rejection(&bytes[..bytes.len() - 1]),
                Rejection::Corrupt(Corruption::Length { .. })
            ),
            "the file must end exactly after the directories"
        );
    }

    #[test]
    fn a_flipped_header_byte_fails_the_header_checksum() {
        let bytes = patched(file(600, 8), 48, &[0x55]);
        assert!(
            matches!(rejection(&bytes), Rejection::Corrupt(Corruption::Checksum)),
            "the count is covered by the checksum"
        );
    }

    #[test]
    fn an_out_of_range_block_shift_is_corrupt() {
        for shift in [0_u8, 17] {
            assert!(
                matches!(
                    rejection(&sealed(10, shift, 72)),
                    Rejection::Corrupt(Corruption::BlockShift(found)) if found == shift
                ),
                "shift {shift} is outside the range the format allows"
            );
        }
    }

    #[test]
    fn a_directory_offset_past_the_file_is_corrupt() {
        assert!(
            matches!(
                rejection(&sealed(0, 8, 5_000)),
                Rejection::Corrupt(Corruption::Length { .. })
            ),
            "the file is shorter than the offset"
        );
    }

    #[test]
    fn a_directory_offset_inside_the_header_is_corrupt() {
        assert!(
            matches!(
                rejection(&sealed(0, 8, 10)),
                Rejection::Corrupt(Corruption::Bounds { .. })
            ),
            "directories cannot overlap the header"
        );
    }

    #[test]
    fn a_block_pointer_past_the_directories_answers_none() {
        let clean = file(600, 8);
        let at = plus(first_entry(&clean), 8);
        let bytes = patched(clean, at, &u64::MAX.to_le_bytes());
        assert_eq!(
            open(&bytes).start(&bytes, 0),
            None,
            "the payload lies outside the file"
        );
    }

    #[test]
    fn a_span_before_a_refused_block_entry_answers_none() {
        let clean = file(600, 8);
        let at = plus(plus(first_entry(&clean), ENTRY_LEN), 8);
        let bytes = patched(clean, at, &u64::MAX.to_le_bytes());
        assert_eq!(
            open(&bytes).span(&bytes, 255),
            None,
            "the successor's block is refused, so the end is unknown and not the mailbox end"
        );
    }

    #[test]
    fn a_width_beyond_sixty_four_answers_none() {
        let clean = file(600, 8);
        let at = plus(first_entry(&clean), 24);
        let bytes = patched(clean, at, &[65]);
        assert_eq!(
            open(&bytes).start(&bytes, 0),
            None,
            "no code is wider than 64 bits"
        );
    }

    #[test]
    fn the_last_position_of_a_block_is_its_highest_held_position() {
        let bytes = file(300, 8);
        let layout = open(&bytes);
        assert_eq!(layout.last_in_block(0), Some(255), "a full block");
        assert_eq!(layout.last_in_block(1), Some(299), "the partial last block");
        assert_eq!(layout.last_in_block(2), None, "a block past the end");
    }

    #[test]
    fn block_size_comes_from_the_header() {
        let wide = file(3_000, 10);
        let small = file(3_000, 8);
        let (wide_layout, small_layout) = (open(&wide), open(&small));
        for position in 0..=3_000 {
            assert_eq!(
                wide_layout.span(&wide, position),
                small_layout.span(&small, position),
                "span {position}"
            );
            assert_eq!(
                wide_layout.date(&wide, position),
                small_layout.date(&small, position),
                "date {position}"
            );
        }
    }

    #[test]
    fn a_push_after_a_short_block_is_refused() {
        let mut writer =
            Writer::new(Cursor::new(Vec::new()), print(), size(2)).expect("the writer starts");
        writer
            .push(&[1, 2], &[Some(1), Some(2)])
            .expect("a short block is allowed once");
        let error = writer
            .push(&[3, 4, 5, 6], &[Some(3), Some(4), Some(5), Some(6)])
            .expect_err("the file is closed");
        assert_eq!(
            error.kind(),
            io::ErrorKind::InvalidInput,
            "short blocks come last"
        );
    }

    #[test]
    fn a_push_of_unequal_lengths_is_refused() {
        let mut writer =
            Writer::new(Cursor::new(Vec::new()), print(), size(2)).expect("the writer starts");
        let error = writer
            .push(&[1, 2], &[Some(1)])
            .expect_err("unequal lengths are refused");
        assert_eq!(
            error.kind(),
            io::ErrorKind::InvalidInput,
            "starts and dates pair up"
        );
    }

    #[test]
    fn an_unfinished_file_reads_as_corrupt() {
        let mut sink = Cursor::new(Vec::new());
        let mut writer = Writer::new(&mut sink, print(), size(2)).expect("the writer starts");
        writer
            .push(&[1, 2, 3, 4], &[Some(1), Some(2), Some(3), Some(4)])
            .expect("a full block");
        drop(writer);
        assert!(
            matches!(
                rejection(&sink.into_inner()),
                Rejection::Corrupt(Corruption::Checksum)
            ),
            "the provisional header has a zero checksum"
        );
    }

    #[test]
    fn spans_tile_a_generated_mailbox() {
        let contents: Vec<u8> = (0..1_000_usize)
            .flat_map(|number| {
                let body = "x".repeat(number.rem_euclid(40));
                format!("From a@b\nSubject: {number}\n\n{body}\n").into_bytes()
            })
            .collect();
        let mailbox = Fingerprint::new(&contents, None);
        let starts: Vec<u64> = scan::find_message_starts(&contents)
            .into_iter()
            .map(widen)
            .collect();
        assert_eq!(starts.len(), 1_000, "every message is found");
        let dates = vec![None; starts.len()];
        let bytes = encode(&starts, &dates, mailbox, BlockSize::default())
            .expect("the starts and dates encode");
        let opened = Layout::parse(&bytes, mailbox).expect("the header is valid");
        for (position, start) in starts.iter().enumerate() {
            let end = starts
                .get(plus(position, 1))
                .map_or_else(|| widen(contents.len()), |next| *next);
            let want = narrow(*start).expect("test offsets fit usize")
                ..narrow(end).expect("test offsets fit usize");
            assert_eq!(opened.span(&bytes, position), Some(want), "span {position}");
        }
        assert_eq!(opened.span(&bytes, starts.len()), None, "None past the end");
    }

    proptest! {
        #[test]
        fn lookups_round_trip_for_any_count_and_shift(count in 0_u64..700, shift in 1_u8..=16) {
            let bytes = file(count, shift);
            let opened = open(&bytes);
            let starts = starts_of(count);
            let dates = dates_of(count);
            for (position, (start, date)) in starts.iter().zip(&dates).enumerate() {
                prop_assert_eq!(opened.start(&bytes, position), Some(*start), "start {}", position);
                prop_assert_eq!(opened.date(&bytes, position), Some(*date), "date {}", position);
            }
        }

        #[test]
        fn damaged_files_never_panic(
            at in 0_usize..40_000,
            value in any::<u8>(),
            junk in vec(any::<u8>(), 0..200),
        ) {
            let mut damaged = file(600, 4);
            if let Some(byte) = damaged.get_mut(at) {
                *byte = value;
            }
            for bytes in [damaged, junk] {
                if let Ok(opened) = Layout::parse(&bytes, print()) {
                    let walked = (0..700)
                        .filter_map(|position| opened.span(&bytes, position))
                        .count();
                    prop_assert!(walked <= 600, "no more spans than messages");
                }
            }
        }
    }
}
