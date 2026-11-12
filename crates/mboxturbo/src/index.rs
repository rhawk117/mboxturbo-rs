//! Message boundary index and its versioned, checksummed on-disk format.

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "wired into the v2 index format by T4")
)]
mod codec;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "wired into the v2 index build by T5 and T8")
)]
mod date;

use std::fs;
use std::io::Write as _;
use std::ops::Range;
use std::path::Path;

use tempfile::NamedTempFile;
use xxhash_rust::xxh3::xxh3_64;

use crate::error::{Corruption, MboxTurboError};
use crate::fingerprint::Fingerprint;
use crate::scan;
use crate::width::{narrow, widen};

/// First eight bytes of every index file.
const MAGIC: [u8; 8] = *b"MBOXTIDX";
/// Format version this build writes and reads; older files count as stale, newer as corrupt.
const VERSION: u32 = 1;
/// Bytes before the first offset: magic, version, reserved word, fingerprint, offset count.
const HEADER_LEN: usize = 56;
/// Size in bytes of one stored offset, count or checksum.
const WORD: usize = 8;

/// Byte offset of every message in one mailbox, tied to that mailbox by its [`Fingerprint`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Index {
    /// Mailbox length in bytes, where the last message stops.
    end: usize,
    /// Identity of the mailbox the offsets were computed from.
    fingerprint: Fingerprint,
    /// Offset where each message starts, strictly increasing and all below `end`.
    starts: Box<[usize]>,
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

impl Index {
    /// Indexes every message in `contents`, scanning segments of it on all rayon threads.
    ///
    /// A message starts at a line beginning with `From `, matching Python's `mailbox.mbox`.
    #[must_use]
    pub fn build(contents: &[u8], fingerprint: Fingerprint) -> Self {
        Self {
            starts: scan::find_message_starts(contents).into_boxed_slice(),
            end: contents.len(),
            fingerprint,
        }
    }

    /// Parses and validates `bytes`, accepting it only for the mailbox `expected` identifies.
    ///
    /// Every length and offset comes from the file, so each is checked before use; nothing here
    /// panics on malformed input.
    fn decode(bytes: &[u8], expected: Fingerprint) -> Result<Self, Rejection> {
        let (body, checksum) = bytes
            .split_last_chunk::<WORD>()
            .ok_or_else(|| truncated(WORD, bytes.len()))?;
        let after_version = check_signature_and_version(body)?;
        if xxh3_64(body) != u64::from_le_bytes(*checksum) {
            return Err(Corruption::Checksum.into());
        }
        let (stored, after_fingerprint) = take_fingerprint(after_version)?;
        if stored != expected {
            return Err(Rejection::Stale);
        }
        let (count, offsets) = take_u64(after_fingerprint)?;
        let starts = decode_starts(offsets, count)?;
        let end = narrow(stored.len()).ok_or(Corruption::MailboxTooLarge {
            length: stored.len(),
        })?;
        validate_starts(&starts, end)?;
        Ok(Self {
            starts,
            end,
            fingerprint: stored,
        })
    }

    /// The on-disk form: header, little-endian offsets, then an xxh3 checksum of all before it.
    fn encode(&self) -> Vec<u8> {
        let offsets_len = self.starts.len().saturating_mul(WORD);
        let mut out =
            Vec::with_capacity(HEADER_LEN.saturating_add(offsets_len).saturating_add(WORD));
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&0_u32.to_le_bytes());
        out.extend_from_slice(&self.fingerprint.len().to_le_bytes());
        out.extend_from_slice(&self.fingerprint.modified_nanos().to_le_bytes());
        out.extend_from_slice(&self.fingerprint.sample_hash().to_le_bytes());
        out.extend_from_slice(&widen(self.starts.len()).to_le_bytes());
        out.extend(
            self.starts
                .iter()
                .flat_map(|&start| widen(start).to_le_bytes()),
        );
        let checksum = xxh3_64(&out);
        out.extend_from_slice(&checksum.to_le_bytes());
        out
    }

    /// Identity of the mailbox this index describes.
    #[must_use]
    pub const fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    /// Whether the mailbox holds no messages.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.starts.is_empty()
    }

    /// Number of messages.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.starts.len()
    }

    /// Reads an index from `path` and checks it was built for the mailbox `expected` identifies.
    ///
    /// # Errors
    ///
    /// [`MboxTurboError::Io`] when the file cannot be read, [`MboxTurboError::CorruptIndex`] when
    /// it fails validation, and [`MboxTurboError::StaleIndex`] when it belongs to a different
    /// mailbox than `expected`.
    pub fn load(path: &Path, expected: Fingerprint) -> Result<Self, MboxTurboError> {
        let bytes = fs::read(path).map_err(|source| MboxTurboError::io(path, source))?;
        Self::decode(&bytes, expected).map_err(|rejection| rejection.at(path))
    }

    /// Writes the index to `path` atomically: readers see the old file or the new one, never a
    /// partial write.
    ///
    /// # Errors
    ///
    /// [`MboxTurboError::Io`] when the temporary file cannot be created, written, synced, or
    /// renamed into place.
    pub fn save(&self, path: &Path) -> Result<(), MboxTurboError> {
        let directory = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty());
        let mut staged = NamedTempFile::new_in(directory.unwrap_or_else(|| Path::new(".")))
            .map_err(|source| MboxTurboError::io(path, source))?;
        staged
            .write_all(&self.encode())
            .map_err(|source| MboxTurboError::io(path, source))?;
        staged
            .as_file()
            .sync_all()
            .map_err(|source| MboxTurboError::io(path, source))?;
        staged
            .persist(path)
            .map(|_persisted| ())
            .map_err(|failure| MboxTurboError::io(path, failure.error))?;
        Ok(())
    }

    /// Byte range of the message at `position`, or `None` past the last message.
    #[must_use]
    pub fn span(&self, position: usize) -> Option<Range<usize>> {
        let mut following = self.starts.get(position..)?.iter().copied();
        let start = following.next()?;
        Some(start..following.next().unwrap_or(self.end))
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

    /// Byte offset where each message starts, in file order.
    #[must_use]
    pub const fn starts(&self) -> &[usize] {
        &self.starts
    }
}

/// Bytes read from the front of a slice, and the slice that remains after them.
type Taken<'bytes, T> = Result<(T, &'bytes [u8]), Corruption>;

/// Checks the magic and version at the start of `body` and returns what follows them.
///
/// An older version is [`Rejection::Stale`] so caches rebuild; a newer one is corrupt.
fn check_signature_and_version(body: &[u8]) -> Result<&[u8], Rejection> {
    let (magic, after_magic) = body.split_first_chunk::<8>().ok_or(Corruption::Signature)?;
    if *magic != MAGIC {
        return Err(Corruption::Signature.into());
    }
    let (version, after_version) = take_u32(after_magic)?;
    if version < VERSION {
        return Err(Rejection::Stale);
    }
    if version != VERSION {
        return Err(Corruption::Version(version).into());
    }
    Ok(after_version)
}

/// Reads the reserved word and the stored [`Fingerprint`] fields from the front of `bytes`.
fn take_fingerprint(bytes: &[u8]) -> Taken<'_, Fingerprint> {
    let (_reserved, after_reserved) = take_u32(bytes)?;
    let (len, after_len) = take_u64(after_reserved)?;
    let (modified, after_modified) = after_len
        .split_first_chunk::<16>()
        .ok_or_else(|| truncated(16, after_len.len()))?;
    let (sample_hash, after_hash) = take_u64(after_modified)?;
    let fingerprint = Fingerprint::from_parts(len, i128::from_le_bytes(*modified), sample_hash);
    Ok((fingerprint, after_hash))
}

/// A [`Corruption::Length`] for a read of `declared` bytes with only `actual` left.
fn truncated(declared: usize, actual: usize) -> Corruption {
    Corruption::Length {
        declared: widen(declared),
        actual: widen(actual),
    }
}

/// Reads a little-endian `u32` from the front of `bytes`, or reports how many bytes were left.
fn take_u32(bytes: &[u8]) -> Taken<'_, u32> {
    let (word, rest) = bytes
        .split_first_chunk::<4>()
        .ok_or_else(|| truncated(4, bytes.len()))?;
    Ok((u32::from_le_bytes(*word), rest))
}

/// Reads a little-endian `u64` from the front of `bytes`, or reports how many bytes were left.
fn take_u64(bytes: &[u8]) -> Taken<'_, u64> {
    let (word, rest) = bytes
        .split_first_chunk::<WORD>()
        .ok_or_else(|| truncated(WORD, bytes.len()))?;
    Ok((u64::from_le_bytes(*word), rest))
}

/// Reads the offset table, which must hold exactly `count` words, rejecting any that exceed
/// `usize`.
fn decode_starts(bytes: &[u8], count: u64) -> Result<Box<[usize]>, Corruption> {
    let (words, remainder) = bytes.as_chunks::<WORD>();
    if !remainder.is_empty() || widen(words.len()) != count {
        return Err(Corruption::Length {
            declared: count.saturating_mul(widen(WORD)),
            actual: widen(bytes.len()),
        });
    }
    words
        .iter()
        .enumerate()
        .map(|(position, &word)| {
            let offset = u64::from_le_bytes(word);
            narrow(offset).ok_or(Corruption::Bounds { position, offset })
        })
        .collect()
}

/// Requires `starts` to be strictly increasing and every offset to lie below `end`.
fn validate_starts(starts: &[usize], end: usize) -> Result<(), Corruption> {
    let disordered = starts
        .windows(2)
        .enumerate()
        .find_map(|(index, pair)| match *pair {
            [previous, offset] if previous >= offset => Some(Corruption::Order {
                position: index.saturating_add(1),
                offset,
                previous,
            }),
            _ => None,
        });
    if let Some(corruption) = disordered {
        return Err(corruption);
    }
    match starts.last() {
        Some(&last) if last >= end => Err(Corruption::Bounds {
            position: starts.len().saturating_sub(1),
            offset: widen(last),
        }),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::{HEADER_LEN, Index, Rejection, xxh3_64};
    use crate::error::Corruption;
    use crate::fingerprint::Fingerprint;

    const MAILBOX: &[u8] = b"From a\nSubject: one\n\nbody\n\nFrom b\nSubject: two\n\nbody\n";

    fn built() -> Index {
        Index::build(MAILBOX, Fingerprint::new(MAILBOX, None))
    }

    fn rejection(bytes: &[u8]) -> Rejection {
        Index::decode(bytes, built().fingerprint()).expect_err("decode must reject")
    }

    #[test]
    fn round_trips_through_its_encoding() {
        let index = built();
        let decoded = Index::decode(&index.encode(), index.fingerprint())
            .expect("an index decodes its own encoding");
        assert_eq!(decoded, index, "decode(encode(x)) == x");
    }

    #[test]
    fn spans_cover_each_message_and_the_last_runs_to_the_end() {
        let index = built();
        assert_eq!(
            index.span(0),
            Some(0..27),
            "the first message spans from its start to the second's start"
        );
        assert_eq!(
            index.span(1),
            Some(27..MAILBOX.len()),
            "the last message runs to the end of the mailbox"
        );
        assert_eq!(
            index.span(2),
            None,
            "a position past the last message has no span"
        );
    }

    #[test]
    fn ranges_of_messages_span_from_the_first_start_to_the_last_end() {
        let index = built();
        assert_eq!(
            index.span_of(0..2),
            Some(0..MAILBOX.len()),
            "a range over every message spans the whole mailbox"
        );
        assert_eq!(
            index.span_of(1..9),
            Some(27..MAILBOX.len()),
            "a range running past the last message is clamped to the mailbox end"
        );
        assert_eq!(
            index.span_of(1..1),
            None,
            "an empty range covers no bytes, so it has no span"
        );
    }

    #[test]
    fn rejects_an_index_built_for_a_different_mailbox() {
        let other = Fingerprint::new(b"From z\n", None);
        let result = Index::decode(&built().encode(), other);
        assert!(
            matches!(result, Err(Rejection::Stale)),
            "fingerprint mismatch is stale"
        );
    }

    #[test]
    fn rejects_a_file_without_the_signature() {
        let mut bytes = built().encode();
        bytes[0] = b'X';
        assert!(
            matches!(rejection(&bytes), Rejection::Corrupt(Corruption::Signature)),
            "a corrupted first byte fails the signature check"
        );
    }

    #[test]
    fn rejects_a_future_format_version() {
        let mut bytes = built().encode();
        bytes[8] = 2;
        assert!(
            matches!(
                rejection(&bytes),
                Rejection::Corrupt(Corruption::Version(2))
            ),
            "a version newer than the format supports is rejected as corrupt"
        );
    }

    #[test]
    fn treats_an_older_format_version_as_stale_so_caches_rebuild() {
        let mut bytes = built().encode();
        bytes[8] = 0;
        assert!(
            matches!(rejection(&bytes), Rejection::Stale),
            "older formats rebuild"
        );
    }

    fn resealed(mut body: Vec<u8>) -> Vec<u8> {
        let checksum = xxh3_64(&body);
        body.extend_from_slice(&checksum.to_le_bytes());
        body
    }

    #[test]
    fn a_file_shorter_than_its_checksum_reports_the_bytes_it_has() {
        assert!(
            matches!(
                rejection(&[0; 3]),
                Rejection::Corrupt(Corruption::Length {
                    declared: 8,
                    actual: 3
                })
            ),
            "three bytes cannot hold a checksum word"
        );
    }

    #[test]
    fn an_offset_table_shorter_than_the_declared_count_reports_both_sizes() {
        let mut body = built().encode();
        body.truncate(body.len() - 16);
        let bytes = resealed(body);
        assert!(
            matches!(
                rejection(&bytes),
                Rejection::Corrupt(Corruption::Length {
                    declared: 16,
                    actual: 8
                })
            ),
            "two offsets are declared and one word is present"
        );
    }

    #[test]
    fn a_start_at_or_past_the_end_names_its_position_and_offset() {
        let mut body = built().encode();
        body.truncate(body.len() - 8);
        let second = HEADER_LEN + 8;
        let past = u64::try_from(MAILBOX.len()).expect("fixture length fits u64");
        body[second..second + 8].copy_from_slice(&past.to_le_bytes());
        let bytes = resealed(body);
        assert!(
            matches!(
                rejection(&bytes),
                Rejection::Corrupt(Corruption::Bounds {
                    position: 1,
                    offset
                }) if offset == past
            ),
            "the second start equals the mailbox length"
        );
    }

    #[test]
    fn rejects_offsets_that_are_out_of_order_even_with_a_valid_checksum() {
        let index = built();
        let mut body = index.encode();
        body.truncate(body.len() - 8);
        let first = HEADER_LEN;
        let second = HEADER_LEN + 8;
        let (head, tail) = body.split_at_mut(second);
        head[first..second].swap_with_slice(&mut tail[..8]);
        let bytes = resealed(body);
        assert!(
            matches!(
                rejection(&bytes),
                Rejection::Corrupt(Corruption::Order {
                    position: 1,
                    offset: 0,
                    previous: 27,
                })
            ),
            "the swapped second start is not after the first"
        );
    }

    proptest! {
        #[test]
        fn rejects_any_single_flipped_bit(byte in 0_usize..96, bit in 0_u8..8) {
            let mut bytes = built().encode();
            let position = byte.checked_rem(bytes.len()).expect("the encoding is never empty");
            bytes[position] ^= 1 << bit;
            prop_assert!(
                Index::decode(&bytes, built().fingerprint()).is_err(),
                "a flipped bit breaks the checksum or a header field"
            );
        }

        #[test]
        fn rejects_any_truncation(cut in 0_usize..96) {
            let bytes = built().encode();
            let kept = cut.checked_rem(bytes.len()).expect("the encoding is never empty");
            prop_assert!(
                Index::decode(&bytes[..kept], built().fingerprint()).is_err(),
                "a truncated file never decodes"
            );
        }
    }
}
