//! The value-plus-issues result every parser returns.

use crate::caps::Cap;
use crate::dkim::RequiredTag;

/// Which of the three ARC headers of a set an [`ArcProblem`] concerns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ArcPart {
    /// The `ARC-Authentication-Results` header.
    AuthenticationResults,
    /// The `ARC-Message-Signature` header.
    MessageSignature,
    /// The `ARC-Seal` header.
    Seal,
}

/// What is wrong with the ARC set an [`IssueKind::ArcInstance`] names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ArcProblem {
    /// The same header kind appeared again for the instance; the first was kept and the
    /// offset is 0 of the repeated header.
    DuplicatePart {
        /// The header kind that repeated.
        part: ArcPart,
    },
    /// No set carries this instance although a higher one exists; the offset is 0.
    Gap,
    /// The `i=` instance is 0 or above 50 (RFC 8617 section 4.2.1); the header was dropped
    /// and the offset points at the `i` tag, or at the number in an `ARC-Authentication-Results`.
    InstanceOutOfRange,
    /// The header has no `i=` instance, so it could not be placed in a set; the offset is the
    /// end of the value and the instance is 0.
    MissingInstance,
    /// The set has no header of this kind; the offset is 0.
    MissingPart {
        /// The header kind that is absent.
        part: ArcPart,
    },
}

/// What went wrong at an [`Issue`]'s offset. New kinds are added as parsers are added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IssueKind {
    /// An ARC set has a problem; `instance` is the `i=` number, 255 when it is larger than
    /// that, and 0 when there is none.
    ArcInstance {
        /// The instance the problem concerns.
        instance: u8,
        /// What is wrong with it.
        problem: ArcProblem,
    },
    /// A date had no time zone, an unknown zone name or a military letter, so UTC was
    /// assumed; the offset points at the zone, or at the end of the value when it is absent.
    AssumedZone,
    /// Input exceeded the named cap and was truncated or skipped.
    CapExceeded {
        /// The bound that was exceeded.
        cap: Cap,
    },
    /// An encoded word had an encoding other than `B` or `Q`, or text that is not valid
    /// base64 or Q encoding; the word was left as raw text.
    InvalidEncoding,
    /// Input was not valid UTF-8 where text was expected; the bytes were decoded lossily.
    InvalidUtf8,
    /// An encoded word decoded to bytes that are not valid in its charset; they became
    /// U+FFFD.
    MalformedBytes,
    /// An `Authentication-Results` value or a DKIM tag list had a structure the grammar does
    /// not allow, such as a result or tag with no `=`, a missing authserv-id, a non-numeric
    /// version or a stray `;`; the entry or pair at the offset was skipped.
    MalformedEntry,
    /// A tag required by the header's grammar is absent from a tag list; the offset is the end
    /// of the value.
    MissingTag {
        /// The name of the absent tag.
        tag: RequiredTag,
    },
    /// A hop's date is earlier than the previous hop's, so its delay is negative; the offset
    /// points at the `;` before the hop's date and the delay is still given.
    NegativeDelay,
    /// A date field was outside its range: a leap second (60) was clamped to 59 and any other
    /// out-of-range field made the date unparsable.
    OutOfRange,
    /// A tag name appeared again in a tag list; the first value was kept and the offset is the
    /// repeated name.
    RepeatedTag,
    /// Text followed a complete date and was ignored.
    TrailingText,
    /// An encoded word named a charset that is unknown, or that has no decoder; the word was
    /// left as raw text.
    UnknownCharset,
    /// A date could not be read at this offset, so no instant was produced.
    UnparsableDate,
    /// A parenthesised comment was still open at the end of the value.
    UnterminatedComment,
    /// A quoted string was still open at the end of the value.
    UnterminatedQuote,
    /// A date named a weekday that is not the weekday of its calendar date; the calendar
    /// date was kept.
    WeekdayMismatch,
    /// A two- or three-digit year was widened to four digits (two digits: 00 to 49 is 20xx,
    /// 50 to 99 is 19xx; three digits add 1900).
    WidenedYear,
}

/// One problem found while parsing, located by byte offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Issue {
    /// What went wrong.
    kind: IssueKind,
    /// Byte offset into the header value where the problem starts.
    offset: usize,
}

impl Issue {
    /// What went wrong.
    #[must_use]
    pub const fn kind(&self) -> IssueKind {
        self.kind
    }

    /// Creates an issue of `kind` at `offset`, a byte offset into the header value.
    #[must_use]
    pub const fn new(kind: IssueKind, offset: usize) -> Self {
        Self { kind, offset }
    }

    /// Byte offset into the header value where the problem starts.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }
}

/// A parsed value together with every [`Issue`] found while recovering it.
///
/// An empty issue list means the input was well formed; otherwise `value` is the best
/// recovery and the issues say where it deviated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed<T> {
    /// The issues found, in the order the parser met them.
    issues: Vec<Issue>,
    /// The recovered value.
    value: T,
}

impl<T> Parsed<T> {
    /// Splits into the value and its issues.
    #[must_use]
    pub fn into_parts(self) -> (T, Vec<Issue>) {
        (self.value, self.issues)
    }

    /// The issues found, in the order the parser met them.
    #[must_use]
    pub fn issues(&self) -> &[Issue] {
        &self.issues
    }

    /// Pairs `value` with the `issues` found while producing it.
    #[must_use]
    pub const fn new(value: T, issues: Vec<Issue>) -> Self {
        Self { issues, value }
    }

    /// The recovered value.
    #[must_use]
    pub const fn value(&self) -> &T {
        &self.value
    }
}

#[cfg(test)]
mod tests {
    use super::{Issue, IssueKind, Parsed};
    use crate::caps::Cap;

    #[test]
    fn a_parsed_value_reads_back_its_value_and_each_issue_kind_and_offset() {
        let issues = vec![
            Issue::new(IssueKind::InvalidUtf8, 3),
            Issue::new(IssueKind::CapExceeded { cap: Cap::Entries }, 40),
        ];
        let parsed = Parsed::new("value", issues);
        assert_eq!(parsed.value(), &"value", "the value is returned unchanged");
        let read: Vec<_> = parsed
            .issues()
            .iter()
            .map(|issue| (issue.kind(), issue.offset()))
            .collect();
        assert_eq!(
            read,
            vec![
                (IssueKind::InvalidUtf8, 3),
                (IssueKind::CapExceeded { cap: Cap::Entries }, 40),
            ],
            "kinds and offsets come back in order",
        );
    }
}
