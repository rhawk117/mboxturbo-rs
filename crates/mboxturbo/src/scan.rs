//! SIMD search for mbox `From ` separator lines, split across threads by newline position.

use std::ops::Range;
use std::vec::IntoIter;

use memchr::memmem::Finder;
use rayon::prelude::*;

/// The bytes that open an mbox message line.
const SEPARATOR: &[u8] = b"From ";
/// A separator preceded by the newline that ends the previous line, so only line starts match.
const BOUNDARY: &[u8] = b"\nFrom ";
/// How many bytes of a boundary can straddle the end of a segment: all but the first.
const BOUNDARY_TAIL: usize = BOUNDARY.len().saturating_sub(1);
/// Bytes per parallel work unit: 16 MiB.
const SEGMENT_LEN: usize = 16 << 20;

/// Segments scanned in parallel per window: 8, so 128 MiB of `contents` at [`SEGMENT_LEN`].
pub(crate) const WINDOW_SEGMENTS: usize = 8;

/// Whether a scan or an encode may spread its work over the global rayon pool.
///
/// A caller that is itself a rayon worker must use [`Parallelism::Sequential`]: its jobs would
/// be stolen by workers that are blocked waiting on that caller, and it, waiting for them, would
/// steal work that waits on it in turn.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Parallelism {
    /// Split the work across the global rayon pool.
    Parallel,
    /// Run every step on the calling thread, touching no rayon pool.
    Sequential,
}

/// Iterator over the message starts of a mailbox, one ascending `Vec` per window in file order.
///
/// An item may be empty. The separator at offset zero, if any, belongs to the first window.
#[derive(Debug)]
pub(crate) struct Windows<'mbox> {
    /// The mailbox bytes being scanned.
    contents: &'mbox [u8],
    /// Searcher for [`BOUNDARY`], shared by every segment.
    finder: Finder<'static>,
    /// The offset of a separator at the very start of `contents`, until the first window takes it.
    leading: Option<usize>,
    /// Whether the segments of a window are scanned on the rayon pool or on this thread.
    parallelism: Parallelism,
    /// Segments not yet scanned.
    segments: IntoIter<Range<usize>>,
    /// Segments scanned in parallel per window, at least one.
    window_segments: usize,
}

impl Iterator for Windows<'_> {
    type Item = Vec<usize>;

    fn next(&mut self) -> Option<Self::Item> {
        let window: Vec<Range<usize>> = self.segments.by_ref().take(self.window_segments).collect();
        if window.is_empty() {
            return None;
        }
        let scan = |segment| starts_in_segment(self.contents, segment, &self.finder);
        let per_segment: Vec<Vec<usize>> = match self.parallelism {
            Parallelism::Parallel => window.into_par_iter().map(scan).collect(),
            Parallelism::Sequential => window.into_iter().map(scan).collect(),
        };
        let mut starts: Vec<usize> = self.leading.take().into_iter().collect();
        starts.extend(per_segment.into_iter().flatten());
        Some(starts)
    }
}

/// Byte offsets of every line in `contents` that begins with `From `, in ascending order.
///
/// Never panics, whatever bytes `contents` holds; empty input yields no offsets.
#[cfg(test)]
pub(crate) fn find_message_starts(contents: &[u8]) -> Vec<usize> {
    windows(contents, Parallelism::Parallel).flatten().collect()
}

/// Message starts of `contents` one window at a time, using [`SEGMENT_LEN`] and
/// [`WINDOW_SEGMENTS`].
pub(crate) fn windows(contents: &[u8], parallelism: Parallelism) -> Windows<'_> {
    windows_with(contents, SEGMENT_LEN, WINDOW_SEGMENTS, parallelism)
}

/// As [`windows`], scanning `segment_len` bytes per parallel unit and `window_segments` units
/// per window, on the threads `parallelism` allows.
///
/// A zero `segment_len` or `window_segments` is treated as one. The concatenated windows are
/// identical for every choice of either.
pub(crate) fn windows_with(
    contents: &[u8],
    segment_len: usize,
    window_segments: usize,
    parallelism: Parallelism,
) -> Windows<'_> {
    Windows {
        contents,
        finder: Finder::new(BOUNDARY),
        parallelism,
        segments: segment_ranges(contents.len(), segment_len).into_iter(),
        window_segments: window_segments.max(1),
        leading: contents.starts_with(SEPARATOR).then_some(0),
    }
}

/// Splits `0..len` into consecutive ranges of `segment_len` bytes, the last one clamped to `len`.
///
/// A `segment_len` of zero is treated as one; `len == 0` yields no ranges.
fn segment_ranges(len: usize, segment_len: usize) -> Vec<Range<usize>> {
    let step = segment_len.max(1);
    (0..len)
        .step_by(step)
        .map(|start| start..start.saturating_add(step).min(len))
        .collect()
}

/// Offsets of the message starts whose preceding newline lies inside `segment`.
///
/// The search window extends past the segment by [`BOUNDARY_TAIL`] bytes so a boundary that
/// straddles the end is found by exactly one segment. A range outside `contents` yields none.
fn starts_in_segment(contents: &[u8], segment: Range<usize>, finder: &Finder<'_>) -> Vec<usize> {
    let window_end = segment
        .end
        .saturating_add(BOUNDARY_TAIL)
        .min(contents.len());
    let owned_len = segment.len();
    contents
        .get(segment.start..window_end)
        .map_or_else(Vec::new, |window| {
            finder
                .find_iter(window)
                .take_while(|&newline| newline < owned_len)
                .map(|newline| segment.start.saturating_add(newline).saturating_add(1))
                .collect()
        })
}

/// The synthetic mbox generator, shared with the integration tests.
///
/// Declared beside `tests` because a path attribute inside an inline module resolves through a
/// directory that does not exist.
#[cfg(test)]
#[path = "../tests/common/mod.rs"]
mod common;

#[cfg(test)]
mod tests {
    use std::fs;

    use proptest::collection::vec;
    use proptest::prelude::*;

    use super::{Parallelism, SEGMENT_LEN, common, find_message_starts, windows_with};

    fn starts_in_segments(contents: &[u8], segment_len: usize) -> Vec<usize> {
        windows_with(contents, segment_len, 1, Parallelism::Parallel)
            .flatten()
            .collect()
    }

    fn line_by_line_reference(contents: &[u8]) -> Vec<usize> {
        let mut starts = Vec::new();
        let mut line_start = 0_usize;
        for line in contents.split_inclusive(|&byte| byte == b'\n') {
            if line.starts_with(b"From ") {
                starts.push(line_start);
            }
            line_start = line_start
                .checked_add(line.len())
                .expect("line offsets stay within the input length");
        }
        starts
    }

    fn mbox_fragments() -> impl Strategy<Value = Vec<u8>> {
        let fragment = prop_oneof![
            Just(b"From ".to_vec()),
            Just(b"\n".to_vec()),
            Just(b"\nFrom ".to_vec()),
            Just(b">From ".to_vec()),
            Just(b"Fro".to_vec()),
            Just(b"m ".to_vec()),
            Just(b"\r\n".to_vec()),
            vec(any::<u8>(), 0..8),
        ];
        vec(fragment, 0..64).prop_map(|parts| parts.concat())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2_000))]

        #[test]
        fn matches_a_line_by_line_scan_at_every_segment_size(
            contents in mbox_fragments(),
            segment_len in 1_usize..48,
        ) {
            prop_assert_eq!(
                starts_in_segments(&contents, segment_len),
                line_by_line_reference(&contents),
                "the parallel scan finds the same starts as a line-by-line scan"
            );
        }
    }

    #[test]
    fn keeps_a_separator_that_starts_exactly_on_a_segment_boundary() {
        let contents = b"From a\nxx\nFrom b\nbody\n";
        let boundary_line = 10;
        assert_eq!(
            &contents[boundary_line..boundary_line + 5],
            b"From ",
            "the fixture has a separator at the segment boundary offset"
        );
        assert_eq!(
            starts_in_segments(contents, boundary_line),
            vec![0, boundary_line],
            "the Python scanner dropped this message"
        );
    }

    #[test]
    fn ignores_leading_junk_before_the_first_separator() {
        assert_eq!(
            find_message_starts(b"junk\nFrom a\n"),
            vec![5],
            "text before the first separator line is not a message"
        );
    }

    #[test]
    fn finds_nothing_in_an_empty_mailbox() {
        assert!(
            find_message_starts(b"").is_empty(),
            "empty input has no messages"
        );
    }

    #[test]
    fn reports_a_separator_that_starts_exactly_on_a_window_boundary_once() {
        let contents = b"From a\nxx\nFrom b\nbody\n";
        let window_boundary = 10;
        assert_eq!(
            windows_with(contents, 5, 2, Parallelism::Parallel)
                .flatten()
                .collect::<Vec<_>>(),
            vec![0, window_boundary],
            "a window boundary neither drops nor repeats the message"
        );
    }

    #[test]
    fn reports_a_separator_after_a_newline_that_opens_a_window_once() {
        let contents = b"From a\nxxx\nFrom b\nbody\n";
        assert_eq!(
            windows_with(contents, 5, 2, Parallelism::Parallel)
                .flatten()
                .collect::<Vec<_>>(),
            vec![0, 11],
            "a newline that opens a window neither drops nor repeats the message"
        );
    }

    #[test]
    fn yields_one_window_per_group_of_segments_in_file_order() {
        let contents = b"From a\nxx\nFrom b\nbody\nFrom c\n";
        let windows: Vec<Vec<usize>> =
            windows_with(contents, 8, 2, Parallelism::Parallel).collect();
        assert_eq!(
            windows,
            vec![vec![0, 10], vec![22]],
            "the first window holds the first two starts, the second the last"
        );
    }

    #[test]
    fn a_zero_segment_length_scans_one_byte_segments_like_a_length_of_one() {
        let contents = b"From a\nx\nFrom b\ny\n";
        let zero: Vec<Vec<usize>> = windows_with(contents, 0, 4, Parallelism::Parallel).collect();
        let one: Vec<Vec<usize>> = windows_with(contents, 1, 4, Parallelism::Parallel).collect();
        assert_eq!(zero, one, "zero is clamped to one, not read as no segments");
        assert_eq!(
            zero.concat(),
            vec![0, 9],
            "the clamped scan still finds both starts"
        );
    }

    #[test]
    fn small_windows_match_a_single_window_over_the_ten_thousand_message_fixture() {
        let directory = tempfile::tempdir().expect("temporary directory is created");
        let spec = common::Spec::default();
        let path = directory.path().join(common::file_name(&spec));
        let summary = common::generate(&path, &spec).expect("the generator writes the fixture");
        assert_eq!(
            summary.messages, spec.messages,
            "the fixture has the default message count"
        );
        let contents = fs::read(&path).expect("the fixture is readable");
        let single_window: Vec<usize> =
            windows_with(&contents, SEGMENT_LEN, usize::MAX, Parallelism::Parallel)
                .flatten()
                .collect();
        let small_windows: Vec<Vec<usize>> =
            windows_with(&contents, 1 << 20, 3, Parallelism::Parallel).collect();
        assert!(
            small_windows.len() > 1,
            "the fixture spans several windows at this size"
        );
        assert_eq!(
            small_windows.into_iter().flatten().collect::<Vec<_>>(),
            single_window,
            "window size does not change the starts"
        );
    }
}
