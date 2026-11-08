//! Message boundary index and its versioned, checksummed on-disk format.

use std::fs;
use std::io::Write as _;
use std::ops::Range;
use std::path::Path;

use tempfile::NamedTempFile;
use xxhash_rust::xxh3::xxh3_64;

use crate::error::{Corruption, MboxturboError};
use crate::fingerprint::Fingerprint;
use crate::scan;
use crate::width::{narrow, widen};

const MAGIC: [u8; 8] = *b"MBOXTIDX";
const VERSION: u32 = 1;
const HEADER_LEN: usize = 56;
const WORD: usize = 8;

/// Byte offset of every message in one mailbox, tied to that mailbox by its [`Fingerprint`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Index {
    starts: Box<[usize]>,
    end: usize,
    fingerprint: Fingerprint,
}

#[derive(Debug)]
enum Rejection {
    Corrupt(Corruption),
    Stale,
}

impl From<Corruption> for Rejection {
    fn from(corruption: Corruption) -> Self {
        Self::Corrupt(corruption)
    }
}

impl Rejection {
    fn at(self, path: &Path) -> MboxturboError {
        let path = path.to_path_buf();
        match self {
            Self::Corrupt(corruption) => MboxturboError::CorruptIndex { path, corruption },
            Self::Stale => MboxturboError::StaleIndex { path },
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

    /// Number of messages.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.starts.len()
    }

    /// Whether the mailbox holds no messages.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.starts.is_empty()
    }

    /// Byte offset where each message starts, in file order.
    #[must_use]
    pub const fn starts(&self) -> &[usize] {
        &self.starts
    }

    /// Identity of the mailbox this index describes.
    #[must_use]
    pub const fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
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

    /// Writes the index to `path` atomically: readers see the old file or the new one, never a
    /// partial write.
    ///
    /// # Errors
    ///
    /// [`MboxturboError::Io`] when the temporary file cannot be created, written, synced, or
    /// renamed into place.
    pub fn save(&self, path: &Path) -> Result<(), MboxturboError> {
        let directory = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty());
        let mut staged = NamedTempFile::new_in(directory.unwrap_or_else(|| Path::new(".")))
            .map_err(|source| MboxturboError::io(path, source))?;
        staged
            .write_all(&self.encode())
            .map_err(|source| MboxturboError::io(path, source))?;
        staged
            .as_file()
            .sync_all()
            .map_err(|source| MboxturboError::io(path, source))?;
        staged
            .persist(path)
            .map(|_persisted| ())
            .map_err(|failure| MboxturboError::io(path, failure.error))?;
        Ok(())
    }

    /// Reads an index from `path` and checks it was built for the mailbox `expected` identifies.
    ///
    /// # Errors
    ///
    /// [`MboxturboError::Io`] when the file cannot be read, [`MboxturboError::CorruptIndex`] when
    /// it fails validation, and [`MboxturboError::StaleIndex`] when it belongs to a different
    /// mailbox than `expected`.
    pub fn load(path: &Path, expected: Fingerprint) -> Result<Self, MboxturboError> {
        let bytes = fs::read(path).map_err(|source| MboxturboError::io(path, source))?;
        Self::decode(&bytes, expected).map_err(|rejection| rejection.at(path))
    }

    fn encode(&self) -> Vec<u8> {
        let offsets_len = self.starts.len().saturating_mul(WORD);
        let mut out =
            Vec::with_capacity(HEADER_LEN.saturating_add(offsets_len).saturating_add(WORD));
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&0_u32.to_le_bytes());
        out.extend_from_slice(&self.fingerprint.len.to_le_bytes());
        out.extend_from_slice(&self.fingerprint.modified_nanos.to_le_bytes());
        out.extend_from_slice(&self.fingerprint.sample_hash.to_le_bytes());
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

    fn decode(bytes: &[u8], expected: Fingerprint) -> Result<Self, Rejection> {
        let (body, checksum) = bytes
            .split_last_chunk::<WORD>()
            .ok_or_else(|| truncated(WORD, bytes.len()))?;
        let (magic, rest) = body.split_first_chunk::<8>().ok_or(Corruption::Signature)?;
        if *magic != MAGIC {
            return Err(Corruption::Signature.into());
        }
        let (version, rest) = take_u32(rest)?;
        if version < VERSION {
            return Err(Rejection::Stale);
        }
        if version != VERSION {
            return Err(Corruption::Version(version).into());
        }
        if xxh3_64(body) != u64::from_le_bytes(*checksum) {
            return Err(Corruption::Checksum.into());
        }
        let (_reserved, rest) = take_u32(rest)?;
        let (len, rest) = take_u64(rest)?;
        let (modified, rest) = rest
            .split_first_chunk::<16>()
            .ok_or_else(|| truncated(16, rest.len()))?;
        let (sample_hash, rest) = take_u64(rest)?;
        let stored = Fingerprint {
            len,
            modified_nanos: i128::from_le_bytes(*modified),
            sample_hash,
        };
        if stored != expected {
            return Err(Rejection::Stale);
        }
        let (count, rest) = take_u64(rest)?;
        let starts = decode_starts(rest, count)?;
        let end = narrow(len).ok_or(Corruption::Bounds {
            position: None,
            offset: len,
        })?;
        validate_starts(&starts, end)?;
        Ok(Self {
            starts,
            end,
            fingerprint: stored,
        })
    }
}

/// A [`Corruption::Length`] for a read of `declared` bytes with only `actual` left.
fn truncated(declared: usize, actual: usize) -> Corruption {
    Corruption::Length {
        declared: widen(declared),
        actual: widen(actual),
    }
}

fn take_u32(bytes: &[u8]) -> Result<(u32, &[u8]), Corruption> {
    let (word, rest) = bytes
        .split_first_chunk::<4>()
        .ok_or_else(|| truncated(4, bytes.len()))?;
    Ok((u32::from_le_bytes(*word), rest))
}

fn take_u64(bytes: &[u8]) -> Result<(u64, &[u8]), Corruption> {
    let (word, rest) = bytes
        .split_first_chunk::<WORD>()
        .ok_or_else(|| truncated(WORD, bytes.len()))?;
    Ok((u64::from_le_bytes(*word), rest))
}

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
            narrow(offset).ok_or(Corruption::Bounds {
                position: Some(position),
                offset,
            })
        })
        .collect()
}

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
            position: Some(starts.len().saturating_sub(1)),
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
        let decoded = Index::decode(&index.encode(), index.fingerprint()).expect("valid encoding");
        assert_eq!(decoded, index, "decode(encode(x)) == x");
    }

    #[test]
    fn spans_cover_each_message_and_the_last_runs_to_the_end() {
        let index = built();
        assert_eq!(index.span(0), Some(0..27), "first message");
        assert_eq!(
            index.span(1),
            Some(27..MAILBOX.len()),
            "last message ends at EOF"
        );
        assert_eq!(index.span(2), None, "past the end");
        assert_eq!(index.span_of(0..2), Some(0..MAILBOX.len()), "whole range");
        assert_eq!(
            index.span_of(1..9),
            Some(27..MAILBOX.len()),
            "clamped range"
        );
        assert_eq!(index.span_of(1..1), None, "empty range");
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
            "magic"
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
            "version"
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
                    position: Some(1),
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
            let position = byte.strict_rem(bytes.len());
            bytes[position] ^= 1 << bit;
            prop_assert!(Index::decode(&bytes, built().fingerprint()).is_err());
        }

        #[test]
        fn rejects_any_truncation(cut in 0_usize..96) {
            let bytes = built().encode();
            let kept = cut.strict_rem(bytes.len());
            prop_assert!(Index::decode(&bytes[..kept], built().fingerprint()).is_err());
        }
    }
}
