//! Parses `--select` and `--select-file` specs into message positions.

use std::fmt;
use std::ops::Range;

/// Why a selection could not be turned into message positions.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum SelectError {
    /// A spec is neither a position nor a half-open `a..b` range.
    Malformed {
        /// The text of the rejected spec.
        spec: String,
    },
    /// A spec names a position at or past the last message.
    OutOfRange {
        /// The number of messages in the mailbox.
        len: usize,
        /// The first position of the selection that is at or past the end of the mailbox.
        position: usize,
    },
}

impl fmt::Display for SelectError {
    #[expect(
        clippy::renamed_function_params,
        reason = "the trait calls it `f`, a one-letter name the min_ident_chars lint bans"
    )]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { spec } => write!(
                formatter,
                "malformed selection `{spec}`: expected a position `N` or a range `A..B`"
            ),
            Self::OutOfRange { len, position } => write!(
                formatter,
                "message position {position} is out of range for a mailbox of {len} messages"
            ),
        }
    }
}

/// Parses every spec list in `lists` into ranges of positions, in the order written.
///
/// # Errors
///
/// [`SelectError::Malformed`] for the first list that does not parse.
pub(crate) fn parse_all(lists: &[String]) -> Result<Vec<Range<usize>>, SelectError> {
    let mut ranges = Vec::new();
    for list in lists {
        ranges.extend(parse_list(list)?);
    }
    Ok(ranges)
}

/// Parses one comma-separated list of specs, each a 0-based position `N` or a half-open range
/// `A..B`, into ranges of positions in the order written.
///
/// # Errors
///
/// [`SelectError::Malformed`] for an empty item, a non-numeric bound, or a range whose start is
/// past its end.
fn parse_list(list: &str) -> Result<Vec<Range<usize>>, SelectError> {
    list.split(',').map(parse_spec).collect()
}

/// Parses one spec: a position `N` (the range `N..N+1`) or a half-open range `A..B`.
fn parse_spec(spec: &str) -> Result<Range<usize>, SelectError> {
    let malformed = || SelectError::Malformed {
        spec: spec.to_owned(),
    };
    let number = |text: &str| text.trim().parse::<usize>().map_err(|_error| malformed());
    let (start, end) = if let Some((first, last)) = spec.split_once("..") {
        (number(first)?, number(last)?)
    } else {
        let position = number(spec)?;
        (position, position.checked_add(1).ok_or_else(malformed)?)
    };
    if start > end {
        return Err(malformed());
    }
    Ok(start..end)
}

/// The sorted, de-duplicated positions the `ranges` cover, checked against a mailbox of `len`
/// messages before any range is expanded so a huge range cannot allocate.
///
/// # Errors
///
/// [`SelectError::OutOfRange`] naming the first position at or past `len`.
pub(crate) fn positions(
    mut ranges: Vec<Range<usize>>,
    len: usize,
) -> Result<Vec<usize>, SelectError> {
    ranges.retain(|range| !range.is_empty());
    if let Some(past) = ranges.iter().find(|range| range.end > len) {
        return Err(SelectError::OutOfRange {
            len,
            position: past.start.max(len),
        });
    }
    ranges.sort_by_key(|range| range.start);
    let mut positions: Vec<usize> = ranges.into_iter().flatten().collect();
    positions.sort_unstable();
    positions.dedup();
    Ok(positions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_single_position_selects_just_that_message() {
        let ranges = parse_list("5").expect("a bare position is well formed");
        assert_eq!(positions(ranges, 10), Ok(vec![5]), "N means only message N");
    }

    #[test]
    fn overlapping_ranges_and_repeats_collapse_to_ascending_positions() {
        let ranges = parse_list("4..6,1..3,2..5,1").expect("every spec is well formed");
        assert_eq!(
            positions(ranges, 10),
            Ok(vec![1, 2, 3, 4, 5]),
            "the union is sorted without duplicates"
        );
    }

    #[test]
    fn an_empty_range_selects_nothing_even_past_the_end() {
        assert_eq!(
            positions(parse_list("9..9").expect("a..a is well formed"), 3),
            Ok(Vec::new()),
            "a..a holds no position"
        );
    }

    #[test]
    fn a_range_running_past_the_end_names_the_first_missing_position() {
        let ranges =
            parse_list("1..9").expect("a range with a start before its end is well formed");
        assert_eq!(
            positions(ranges, 4),
            Err(SelectError::OutOfRange {
                len: 4,
                position: 4
            }),
            "positions 4.. do not exist"
        );
    }

    #[test]
    fn a_start_past_the_end_names_that_start() {
        let ranges =
            parse_list("7..9").expect("a range with a start before its end is well formed");
        assert_eq!(
            positions(ranges, 4),
            Err(SelectError::OutOfRange {
                len: 4,
                position: 7
            }),
            "the range starts after the last message"
        );
    }

    #[test]
    fn malformed_specs_are_rejected_with_their_text() {
        for bad in ["", "a", "-1", "3..1", "1..2..3", "1,,2", "..", "1.."] {
            assert!(
                matches!(parse_list(bad), Err(SelectError::Malformed { .. })),
                "`{bad}` is not a valid selection"
            );
        }
    }

    #[test]
    fn the_largest_position_does_not_overflow_the_range_end() {
        let max = usize::MAX.to_string();
        assert_eq!(
            parse_list(&max),
            Err(SelectError::Malformed { spec: max }),
            "MAX..MAX+1 is unrepresentable"
        );
    }
}
