//! The value-plus-issues result every parser returns.

use crate::caps::Cap;

/// What went wrong at an [`Issue`]'s offset. New kinds are added as parsers are added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IssueKind {
    /// Input exceeded the named cap and was truncated or skipped.
    CapExceeded {
        /// The bound that was exceeded.
        cap: Cap,
    },
    /// Input was not valid UTF-8 where text was expected; the bytes were decoded lossily.
    InvalidUtf8,
    /// A parenthesised comment was still open at the end of the value.
    UnterminatedComment,
    /// A quoted string was still open at the end of the value.
    UnterminatedQuote,
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
