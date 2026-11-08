//! SIMD search for mbox `From ` separator lines, split across threads by newline position.

use std::ops::Range;

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

/// Byte offsets of every line in `contents` that begins with `From `, in ascending order.
///
/// Never panics, whatever bytes `contents` holds; empty input yields no offsets.
pub(crate) fn find_message_starts(contents: &[u8]) -> Vec<usize> {
    find_message_starts_in_segments(contents, SEGMENT_LEN)
}

/// As [`find_message_starts`], scanning `segment_len` bytes per parallel unit.
///
/// A `segment_len` of zero is treated as one. The result is identical for every segment size.
pub(crate) fn find_message_starts_in_segments(contents: &[u8], segment_len: usize) -> Vec<usize> {
    let finder = Finder::new(BOUNDARY);
    let per_segment: Vec<Vec<usize>> = segment_ranges(contents.len(), segment_len)
        .into_par_iter()
        .map(|segment| starts_in_segment(contents, segment, &finder))
        .collect();
    let leading = contents.starts_with(SEPARATOR).then_some(0);
    let total = per_segment
        .iter()
        .map(Vec::len)
        .sum::<usize>()
        .saturating_add(1);
    let mut starts = Vec::with_capacity(total);
    starts.extend(leading);
    starts.extend(per_segment.into_iter().flatten());
    starts
}

/// Splits `0..len` into consecutive ranges of `segment_len` bytes, the last one clamped to `len`.
///
/// A `segment_len` of zero is treated as one; `len == 0` yields no ranges.
fn segment_ranges(len: usize, segment_len: usize) -> Vec<Range<usize>> {
    (0..len)
        .step_by(segment_len.max(1))
        .map(|start| start..start.saturating_add(segment_len).min(len))
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

#[cfg(test)]
mod tests {
    use proptest::collection::vec;
    use proptest::prelude::*;

    use super::{find_message_starts, find_message_starts_in_segments};

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
                find_message_starts_in_segments(&contents, segment_len),
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
            find_message_starts_in_segments(contents, boundary_line),
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
}
