//! The date window a narrowing keeps, and the one place a date is compared with it.

/// A window over index dates, in unix seconds: `since` is inclusive and `until` is exclusive.
/// A `None` side is open, so the default window admits every dated message.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DateBounds {
    /// The inclusive lower bound, or `None` for no lower bound.
    since: Option<i64>,
    /// The exclusive upper bound, or `None` for no upper bound.
    until: Option<i64>,
}

impl DateBounds {
    /// Whether `date` is at or after `since` and before `until`.
    #[must_use]
    pub fn admits(&self, date: i64) -> bool {
        self.since.is_none_or(|bound| bound <= date) && self.until.is_none_or(|bound| date < bound)
    }

    /// Whether neither side is bounded, so a message with no index date is kept too.
    #[must_use]
    pub const fn is_unbounded(&self) -> bool {
        self.since.is_none() && self.until.is_none()
    }

    /// The bounds from an inclusive `since` and an exclusive `until`; `None` leaves that side open.
    #[must_use]
    pub const fn new(since: Option<i64>, until: Option<i64>) -> Self {
        Self { since, until }
    }
}
