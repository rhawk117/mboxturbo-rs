//! Identity of a mailbox file, used to tell whether a saved index still matches it.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use xxhash_rust::xxh3::Xxh3;

use crate::width::widen;

const SAMPLE_LEN: usize = 4096;

/// Identity of a mailbox: its length, modification time, and a hash of its first and last
/// 4 KiB. Two fingerprints are equal only when all three match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint {
    pub(crate) len: u64,
    pub(crate) modified_nanos: i128,
    pub(crate) sample_hash: u64,
}

impl Fingerprint {
    /// Fingerprints mailbox `contents` last modified at `modified`, if known.
    #[must_use]
    pub fn new(contents: &[u8], modified: Option<SystemTime>) -> Self {
        Self {
            len: widen(contents.len()),
            modified_nanos: modified.map_or(0, nanos_since_epoch),
            sample_hash: sample_hash(contents),
        }
    }

    /// Length in bytes of the fingerprinted mailbox.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.len
    }

    /// Whether the fingerprinted mailbox was empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

fn sample_hash(contents: &[u8]) -> u64 {
    let head = contents.get(..SAMPLE_LEN).unwrap_or(contents);
    let tail = contents
        .get(contents.len().saturating_sub(SAMPLE_LEN)..)
        .unwrap_or(contents);
    let mut hasher = Xxh3::new();
    hasher.update(&widen(contents.len()).to_le_bytes());
    hasher.update(head);
    hasher.update(tail);
    hasher.digest()
}

fn nanos_since_epoch(time: SystemTime) -> i128 {
    time.duration_since(UNIX_EPOCH).map_or_else(
        |before| signed_nanos(before.duration()).saturating_neg(),
        signed_nanos,
    )
}

fn signed_nanos(span: Duration) -> i128 {
    i128::try_from(span.as_nanos()).unwrap_or(i128::MAX)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::Fingerprint;

    #[test]
    fn differs_when_any_byte_in_the_sampled_tail_changes() {
        let original = vec![b'a'; 10_000];
        let mut edited = original.clone();
        edited[9_999] = b'b';
        assert_ne!(
            Fingerprint::new(&original, None),
            Fingerprint::new(&edited, None),
            "tail edit must change the fingerprint"
        );
    }

    #[test]
    fn differs_when_only_the_modification_time_changes() {
        let contents = b"From a\n\nbody\n";
        let earlier = Fingerprint::new(contents, Some(UNIX_EPOCH + Duration::from_secs(10)));
        let later = Fingerprint::new(contents, Some(UNIX_EPOCH + Duration::from_secs(11)));
        assert_ne!(earlier, later, "mtime change must change the fingerprint");
    }

    #[test]
    fn represents_times_before_the_epoch_as_negative() {
        let before = UNIX_EPOCH - Duration::from_secs(5);
        let fingerprint = Fingerprint::new(b"", Some(before));
        assert_eq!(
            fingerprint.modified_nanos, -5_000_000_000,
            "pre-epoch time is negative"
        );
    }
}
