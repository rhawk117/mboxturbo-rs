//! Which messages of a mailbox a batch reader visits, and in what order.

use std::iter;
use std::ops::Range;
use std::sync::Arc;

use crate::error::MboxTurboError;

/// The message positions a [`BatchReader`](crate::BatchReader) yields, in the order given.
///
/// Positions are zero-based message indexes. A selection is validated against the mailbox
/// length up front by [`Pipeline::select`](crate::Pipeline::select).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Selection {
    /// Every message, in mailbox order.
    All,
    /// Exactly these positions, in this order; repeats and descending order are kept.
    Positions(Vec<usize>),
    /// The positions of each range in turn; empty ranges contribute nothing and ranges may
    /// repeat or descend relative to one another.
    Ranges(Vec<Range<usize>>),
}

/// A validated selection as non-empty runs of consecutive positions, with a read cursor.
#[derive(Debug, Clone)]
pub(crate) struct Plan {
    /// Index of the run holding the first position not yet taken.
    run: usize,
    /// Non-empty runs in yield order.
    runs: Arc<[Range<usize>]>,
    /// Number of positions across all runs.
    total: usize,
    /// Offset into the current run of the first position not yet taken.
    within: usize,
}

impl Selection {
    /// Validates every position against a mailbox of `len` messages and plans the walk.
    ///
    /// # Errors
    ///
    /// [`MboxTurboError::PositionOutOfRange`] naming the first position at or past `len`.
    pub(crate) fn plan(self, len: usize) -> Result<Plan, MboxTurboError> {
        let runs = match self {
            Self::All => return Ok(Plan::whole(len)),
            Self::Ranges(ranges) => checked_ranges(ranges, len)?,
            Self::Positions(positions) => checked_positions(&positions, len)?,
        };
        Ok(Plan::new(runs))
    }
}

impl Plan {
    /// A plan over `candidates`, dropping empty ones.
    fn new(candidates: impl IntoIterator<Item = Range<usize>>) -> Self {
        let runs: Arc<[Range<usize>]> = candidates
            .into_iter()
            .filter(|run| !run.is_empty())
            .collect();
        let total = runs.iter().map(Range::len).fold(0, usize::saturating_add);
        Self {
            within: 0,
            run: 0,
            runs,
            total,
        }
    }

    /// Takes the next `count` positions (fewer at the end) as consecutive-position ranges, and
    /// advances past them.
    pub(crate) fn take(&mut self, count: usize) -> Vec<Range<usize>> {
        let mut taken: Vec<Range<usize>> = Vec::new();
        let mut remaining = count;
        while remaining > 0 {
            let Some(run) = self.runs.get(self.run) else {
                break;
            };
            let start = run.start.saturating_add(self.within);
            let step = run.end.saturating_sub(start).min(remaining);
            let end = start.saturating_add(step);
            match taken.last_mut() {
                Some(last) if last.end == start => last.end = end,
                _ => taken.push(start..end),
            }
            remaining = remaining.saturating_sub(step);
            if end == run.end {
                self.run = self.run.saturating_add(1);
                self.within = 0;
            } else {
                self.within = self.within.saturating_add(step);
            }
        }
        taken
    }

    /// Number of positions the selection yields in total.
    pub(crate) const fn total(&self) -> usize {
        self.total
    }

    /// A plan over every message of a mailbox of `len` messages.
    pub(crate) fn whole(len: usize) -> Self {
        Self::new(iter::once(0..len))
    }
}

/// `ranges` unchanged when every non-empty one ends within `len`.
fn checked_ranges(
    ranges: Vec<Range<usize>>,
    len: usize,
) -> Result<Vec<Range<usize>>, MboxTurboError> {
    let past = ranges
        .iter()
        .filter(|range| !range.is_empty() && range.end > len)
        .map(|range| range.start.max(len))
        .next();
    past.map_or_else(
        || Ok(ranges),
        |position| Err(MboxTurboError::PositionOutOfRange { position, len }),
    )
}

/// `positions` grouped into runs of consecutive positions, when each is below `len`.
fn checked_positions(positions: &[usize], len: usize) -> Result<Vec<Range<usize>>, MboxTurboError> {
    if let Some(&position) = positions.iter().find(|&&position| position >= len) {
        return Err(MboxTurboError::PositionOutOfRange { position, len });
    }
    let mut runs: Vec<Range<usize>> = Vec::new();
    for &position in positions {
        let next = position.saturating_add(1);
        match runs.last_mut() {
            Some(last) if last.end == position => last.end = next,
            _ => runs.push(position..next),
        }
    }
    Ok(runs)
}

#[cfg(test)]
mod tests {
    use super::Selection;
    use crate::error::MboxTurboError;

    #[test]
    fn take_walks_runs_across_their_boundaries_in_order() {
        let mut plan = Selection::Ranges(vec![5..7, 2..4, 7..9])
            .plan(10)
            .expect("ranges are within the mailbox");
        assert_eq!(plan.total(), 6, "2 + 2 + 2 positions");
        assert_eq!(plan.take(3), [5..7, 2..3], "a batch may span two runs");
        assert_eq!(plan.take(9), [3..4, 7..9], "the rest, shorter than asked");
        assert!(plan.take(1).is_empty(), "nothing is left");
    }

    #[test]
    fn an_out_of_range_position_is_named_with_the_length() {
        let error = Selection::Positions(vec![0, 3, 1])
            .plan(3)
            .expect_err("position 3 is past a mailbox of 3");
        assert!(
            matches!(
                error,
                MboxTurboError::PositionOutOfRange {
                    position: 3,
                    len: 3
                }
            ),
            "the error names position 3 and length 3"
        );
    }
}
