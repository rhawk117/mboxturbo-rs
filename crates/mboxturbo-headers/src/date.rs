//! Lenient `Date` parsing: RFC 5322 (with its obsolete forms), asctime and ISO 8601 values
//! become a UTC instant plus the offset they were written with.
//!
//! Every guess made on the way is reported as an [`Issue`]: an assumed zone, a weekday that
//! disagrees with the date, a widened year, a clamped or rejected field and ignored trailing
//! text. The parsers make one pass over the tokens (or bytes) of the value, so the work is
//! linear in its length.

use std::ops::RangeInclusive;

use crate::issue::{Issue, IssueKind, Parsed};
use crate::tokenize::{Token, TokenKind, bound, slice_checked, tokenize};

/// Seconds in a day.
const DAY_SECONDS: i64 = 86_400;

/// Microseconds in a second.
const MICROS_PER_SECOND: i64 = 1_000_000;

/// Month names by their first three letters; month numbers start at 1.
const MONTHS: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];

/// Time zone names RFC 5322 defines, with their offsets in minutes east of UTC.
const NAMED_ZONES: [(&str, i16); 10] = [
    ("ut", 0),
    ("gmt", 0),
    ("est", -300),
    ("edt", -240),
    ("cst", -360),
    ("cdt", -300),
    ("mst", -420),
    ("mdt", -360),
    ("pst", -480),
    ("pdt", -420),
];

/// Weekday names by their first three letters; Sunday is 0.
const WEEKDAYS: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

/// A position in the non-comment tokens of a value.
#[derive(Debug)]
struct Cursor<'tok> {
    /// Byte length of the value, where a missing zone is reported.
    end: usize,
    /// The issues found so far, including the tokenizer's.
    issues: Vec<Issue>,
    /// Index of the next unread token in `words`.
    position: usize,
    /// The tokens other than comments.
    words: Vec<&'tok Token<'tok>>,
}

impl<'tok> Cursor<'tok> {
    /// Reads `Mon Jan  1 12:00:00 2024` after the weekday, with an optional zone at the end.
    fn asctime_fields(&mut self, weekday: Option<Weekday>) -> Option<Fields> {
        let month = self.month()?;
        let day = self.day()?;
        let time = self.time()?;
        let year = self.year()?;
        let zone_minutes = self.zone()?;
        Some(Fields {
            day,
            month,
            time,
            weekday,
            year,
            zone_minutes,
        })
    }

    /// Reports a zone that had to be assumed to be UTC.
    fn assume_zone(&mut self, offset: usize) -> i16 {
        self.issues.push(Issue::new(IssueKind::AssumedZone, offset));
        0
    }

    /// Advances past the current token.
    const fn bump(&mut self) {
        self.position = self.position.saturating_add(1);
    }

    /// The minutes of a `+01:00` zone, once its hours are read.
    fn colon_minutes(&mut self) -> Option<Number> {
        if self.eat_special(b':') {
            return self.number();
        }
        None
    }

    /// Reads a day of the month, 1 to 31.
    fn day(&mut self) -> Option<Number> {
        let number = self.required()?;
        day_of(&mut self.issues, number)
    }

    /// Consumes `byte` when it is the next token.
    fn eat_special(&mut self, byte: u8) -> bool {
        let found = self
            .peek()
            .is_some_and(|token| token.kind() == TokenKind::Special(byte));
        if found {
            self.bump();
        }
        found
    }

    /// Reports an unreadable date at the current token and gives up.
    fn fail<T>(&mut self) -> Option<T> {
        let offset = self.peek().map_or(self.end, Token::offset);
        self.issues
            .push(Issue::new(IssueKind::UnparsableDate, offset));
        None
    }

    /// The instant of an RFC 5322 or asctime value, or `None` with an issue.
    fn instant(&mut self) -> Option<Instant> {
        let weekday = self.weekday();
        let fields = if self.month_ahead() {
            self.asctime_fields(weekday)?
        } else {
            self.rfc_fields(weekday)?
        };
        if let Some(token) = self.peek() {
            let offset = token.offset();
            self.issues
                .push(Issue::new(IssueKind::TrailingText, offset));
        }
        instant_of(&mut self.issues, &fields)
    }

    /// Consumes a month name and gives its number, 1 to 12.
    fn month(&mut self) -> Option<i16> {
        let found = self
            .peek()
            .and_then(|token| name_index(&MONTHS, token.text(), 1));
        let Some(month) = found else {
            return self.fail();
        };
        self.bump();
        Some(month)
    }

    /// Whether the next token is a month name.
    fn month_ahead(&self) -> bool {
        self.peek()
            .is_some_and(|token| name_index(&MONTHS, token.text(), 1).is_some())
    }

    /// Creates a cursor over the non-comment `tokens`, continuing the tokenizer's `issues`.
    fn new(tokens: &'tok [Token<'tok>], issues: Vec<Issue>, end: usize) -> Self {
        let words = tokens
            .iter()
            .filter(|token| token.kind() != TokenKind::Comment)
            .collect();
        Self {
            end,
            issues,
            position: 0,
            words,
        }
    }

    /// Consumes the next token when it is one to four digits.
    fn number(&mut self) -> Option<Number> {
        let token = self.peek().filter(|word| word.kind() == TokenKind::Atom)?;
        let number = number_of(token.text().as_bytes(), token.offset())?;
        self.bump();
        Some(number)
    }

    /// Reads the zone `+0100`, `+01:00` or `+01` in `token`, which is the next token.
    fn numeric_zone(&mut self, token: &Token<'_>, sign: Sign) -> Option<i16> {
        self.bump();
        let offset = token.offset();
        let text = token.text().as_bytes();
        let digits = slice_checked(text, offset, 1..text.len(), &mut self.issues);
        let digits_offset = offset.saturating_add(1);
        let pieces = match digits.len() {
            4 => number_of(digits.get(..2)?, digits_offset).zip(Some(number_of(
                digits.get(2..)?,
                digits_offset.saturating_add(2),
            ))),
            2 => number_of(digits, digits_offset).zip(Some(self.colon_minutes())),
            _ => None,
        };
        let Some((hours, minutes)) = pieces else {
            return Some(self.assume_zone(offset));
        };
        zone_magnitude(&mut self.issues, hours, minutes).map(|total| sign.apply(total))
    }

    /// The next unread token.
    fn peek(&self) -> Option<&'tok Token<'tok>> {
        self.words.get(self.position).copied()
    }

    /// Consumes `byte` or reports an unreadable date.
    fn require_special(&mut self, byte: u8) -> Option<()> {
        if self.eat_special(byte) {
            return Some(());
        }
        self.fail()
    }

    /// Consumes a number, or reports an unreadable date.
    fn required(&mut self) -> Option<Number> {
        let Some(number) = self.number() else {
            return self.fail();
        };
        Some(number)
    }

    /// Consumes a number in `range`, or reports why not.
    fn required_in(&mut self, range: RangeInclusive<i16>) -> Option<i16> {
        let number = self.required()?;
        ranged(&mut self.issues, number, range)
    }

    /// Reads `day month year time zone` after the weekday.
    fn rfc_fields(&mut self, weekday: Option<Weekday>) -> Option<Fields> {
        let day = self.day()?;
        let month = self.month()?;
        let year = self.year()?;
        let time = self.time()?;
        let zone_minutes = self.zone()?;
        Some(Fields {
            day,
            month,
            time,
            weekday,
            year,
            zone_minutes,
        })
    }

    /// Reads `:ss` when present; no seconds is zero.
    fn second(&mut self) -> Option<i16> {
        if !self.eat_special(b':') {
            return Some(0);
        }
        let number = self.required()?;
        seconds(&mut self.issues, number)
    }

    /// Consumes a comma when it is the next token.
    fn skip_comma(&mut self) {
        let comma = self
            .peek()
            .is_some_and(|token| token.kind() == TokenKind::Special(b','));
        if comma {
            self.bump();
        }
    }

    /// Reads `hh:mm` or `hh:mm:ss`.
    fn time(&mut self) -> Option<Time> {
        let hour = self.required_in(0..=23)?;
        self.require_special(b':')?;
        let minute = self.required_in(0..=59)?;
        let second = self.second()?;
        Some(Time {
            hour,
            minute,
            second,
        })
    }

    /// Consumes an optional weekday name and the comma after it.
    fn weekday(&mut self) -> Option<Weekday> {
        let token = self.peek().filter(|word| word.kind() == TokenKind::Atom)?;
        let value = name_index(&WEEKDAYS, token.text(), 0)?;
        self.bump();
        self.skip_comma();
        Some(Weekday {
            offset: token.offset(),
            value,
        })
    }

    /// Reads and widens the year.
    fn year(&mut self) -> Option<i16> {
        let number = self.required()?;
        widen_year(&mut self.issues, number)
    }

    /// Reads the zone, assuming UTC and reporting it when absent or not understood.
    fn zone(&mut self) -> Option<i16> {
        let Some(token) = self.peek().filter(|word| word.kind() == TokenKind::Atom) else {
            return Some(self.assume_zone(self.end));
        };
        let first = token.text().bytes().next().and_then(Sign::of);
        if let Some(sign) = first {
            return self.numeric_zone(token, sign);
        }
        self.bump();
        let text = token.text();
        let named = NAMED_ZONES
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(text))
            .map(|(_, minutes)| *minutes);
        if named.is_some() {
            return named;
        }
        if text.eq_ignore_ascii_case("z") {
            return Some(0);
        }
        Some(self.assume_zone(token.offset()))
    }
}

/// Everything read from a value, before the calendar checks.
#[derive(Debug, Clone, Copy)]
struct Fields {
    /// The day of the month as written.
    day: Number,
    /// Month, 1 to 12.
    month: i16,
    /// The time of day.
    time: Time,
    /// A weekday name, when the value had one.
    weekday: Option<Weekday>,
    /// Four-digit year.
    year: i16,
    /// Minutes east of UTC.
    zone_minutes: i16,
}

/// A moment in time with the zone offset the message gave it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Instant {
    /// Minutes east of UTC that the original value was written in.
    offset_minutes: i16,
    /// Seconds since 1970-01-01T00:00:00Z.
    unix_seconds: i64,
}

impl Instant {
    /// Minutes east of UTC that the value was written in, between -1439 and 1439. Zero when
    /// the zone was UTC or had to be assumed.
    #[must_use]
    pub const fn offset_minutes(&self) -> i16 {
        self.offset_minutes
    }

    /// Seconds since the Unix epoch, in UTC.
    #[must_use]
    pub const fn unix_seconds(&self) -> i64 {
        self.unix_seconds
    }
}

/// A run of one to four ASCII digits.
#[derive(Debug, Clone, Copy)]
struct Number {
    /// How many digits were written.
    digits: usize,
    /// Byte offset of the first digit in the value.
    offset: usize,
    /// The value read.
    value: i16,
}

/// A position in the bytes of an ISO 8601 value.
#[derive(Debug)]
struct Raw<'src> {
    /// The issues found so far.
    issues: Vec<Issue>,
    /// Index of the next unread byte.
    position: usize,
    /// The whole value.
    value: &'src [u8],
}

impl<'src> Raw<'src> {
    /// Moves past `count` bytes.
    const fn advance(&mut self, count: usize) {
        self.position = self.position.saturating_add(count);
    }

    /// Reads exactly `count` digits.
    fn digits(&mut self, count: usize) -> Option<Number> {
        let end = self.position.saturating_add(count);
        let number = self
            .value
            .get(self.position..end)
            .filter(|bytes| bytes.len() == count)
            .and_then(|bytes| number_of(bytes, self.position));
        let Some(found) = number else {
            return self.fail();
        };
        self.advance(count);
        Some(found)
    }

    /// Reads exactly `count` digits whose value lies in `range`, or reports why not.
    fn digits_in(&mut self, count: usize, range: RangeInclusive<i16>) -> Option<i16> {
        let number = self.digits(count)?;
        ranged(&mut self.issues, number, range)
    }

    /// Consumes `byte` when it is next.
    fn eat(&mut self, byte: u8) -> bool {
        let found = self.peek() == Some(byte);
        if found {
            self.advance(1);
        }
        found
    }

    /// Reports an unreadable date at the current byte and gives up.
    fn fail<T>(&mut self) -> Option<T> {
        self.issues
            .push(Issue::new(IssueKind::UnparsableDate, self.position));
        None
    }

    /// Reads `yyyy-mm-dd` with an optional time and zone.
    fn fields(&mut self) -> Option<Fields> {
        let year = self.digits(4)?.value;
        self.require(b'-')?;
        let month = self.digits_in(2, 1..=12)?;
        self.require(b'-')?;
        let day_number = self.digits(2)?;
        let day = day_of(&mut self.issues, day_number)?;
        let time = self.time()?;
        let zone_minutes = self.zone()?;
        Some(Fields {
            day,
            month,
            time,
            weekday: None,
            year,
            zone_minutes,
        })
    }

    /// The instant of an ISO 8601 value, or `None` with an issue.
    fn instant(&mut self) -> Option<Instant> {
        let fields = self.fields()?;
        self.skip_space();
        if self.position < self.value.len() {
            self.issues
                .push(Issue::new(IssueKind::TrailingText, self.position));
        }
        instant_of(&mut self.issues, &fields)
    }

    /// Whether the value starts, after whitespace, with four digits and a hyphen; moves to
    /// that point when it does.
    fn looks_iso(&mut self) -> bool {
        self.skip_space();
        let rest = slice_checked(
            self.value,
            0,
            self.position..self.value.len(),
            &mut self.issues,
        );
        let year = rest
            .get(..4)
            .is_some_and(|bytes| bytes.iter().all(u8::is_ascii_digit));
        year && rest.get(4) == Some(&b'-')
    }

    /// Creates a cursor at the start of `value`.
    const fn new(value: &'src [u8]) -> Self {
        Self {
            issues: Vec::new(),
            position: 0,
            value,
        }
    }

    /// The next unread byte.
    fn peek(&self) -> Option<u8> {
        self.value.get(self.position).copied()
    }

    /// Consumes `byte` or reports an unreadable date.
    fn require(&mut self, byte: u8) -> Option<()> {
        if self.eat(byte) {
            return Some(());
        }
        self.fail()
    }

    /// Reads `:ss` and an ignored fraction when present; no seconds is zero.
    fn second(&mut self) -> Option<i16> {
        if !self.eat(b':') {
            return Some(0);
        }
        let number = self.digits(2)?;
        self.skip_fraction();
        seconds(&mut self.issues, number)
    }

    /// Skips `.123` or `,123` after the seconds.
    fn skip_fraction(&mut self) {
        if self.eat(b'.') || self.eat(b',') {
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.advance(1);
            }
        }
    }

    /// Skips ASCII whitespace.
    fn skip_space(&mut self) {
        while self.peek().is_some_and(|byte| byte.is_ascii_whitespace()) {
            self.advance(1);
        }
    }

    /// Reads an optional `Thh:mm:ss`; a date alone is midnight.
    fn time(&mut self) -> Option<Time> {
        if !(self.eat(b'T') || self.eat(b't') || self.eat(b' ')) {
            return Some(Time {
                hour: 0,
                minute: 0,
                second: 0,
            });
        }
        let hour = self.digits_in(2, 0..=23)?;
        self.require(b':')?;
        let minute = self.digits_in(2, 0..=59)?;
        let second = self.second()?;
        Some(Time {
            hour,
            minute,
            second,
        })
    }

    /// Reads `Z`, `+hh:mm`, `+hhmm` or `+hh`; a missing zone is assumed to be UTC.
    fn zone(&mut self) -> Option<i16> {
        if self.eat(b'Z') || self.eat(b'z') {
            return Some(0);
        }
        let Some(sign) = self.peek().and_then(Sign::of) else {
            self.issues
                .push(Issue::new(IssueKind::AssumedZone, self.position));
            return Some(0);
        };
        self.advance(1);
        let hours = self.digits(2)?;
        let _colon = self.eat(b':');
        let minutes = if self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            Some(self.digits(2)?)
        } else {
            None
        };
        zone_magnitude(&mut self.issues, hours, minutes).map(|total| sign.apply(total))
    }
}

/// Which side of UTC a written zone lies on.
#[derive(Debug, Clone, Copy)]
enum Sign {
    /// `+`: ahead of UTC.
    East,
    /// `-`: behind UTC.
    West,
}

impl Sign {
    /// Gives `minutes` this sign.
    const fn apply(self, minutes: i16) -> i16 {
        match self {
            Self::East => minutes,
            Self::West => minutes.saturating_neg(),
        }
    }

    /// The sign `byte` writes, if it is `+` or `-`.
    const fn of(byte: u8) -> Option<Self> {
        match byte {
            b'+' => Some(Self::East),
            b'-' => Some(Self::West),
            _ => None,
        }
    }
}

/// The time of day.
#[derive(Debug, Clone, Copy)]
struct Time {
    /// Hour, 0 to 23.
    hour: i16,
    /// Minute, 0 to 59.
    minute: i16,
    /// Second, 0 to 59 after clamping a leap second.
    second: i16,
}

/// A weekday name that preceded the date.
#[derive(Debug, Clone, Copy)]
struct Weekday {
    /// Byte offset of the name in the value.
    offset: usize,
    /// Days after Sunday.
    value: i16,
}

/// Reports a weekday name that is not the weekday of `days` after the epoch.
fn check_weekday(issues: &mut Vec<Issue>, weekday: Option<Weekday>, days: i64) {
    let Some(named) = weekday else {
        return;
    };
    // 1970-01-01 was a Thursday, day 4 counting from Sunday.
    if days.saturating_add(4).rem_euclid(7) != i64::from(named.value) {
        issues.push(Issue::new(IssueKind::WeekdayMismatch, named.offset));
    }
}

/// Reports a day outside 1 to 31, otherwise gives `number` back.
fn day_of(issues: &mut Vec<Issue>, number: Number) -> Option<Number> {
    ranged(issues, number, 1..=31).map(|_| number)
}

/// The instant of `value` when it is exactly `[Www, ]D[D] Mon YYYY HH:MM[:SS] +ZZZZ` in single
/// spaces and raises no issue; `None` for every other value, which the general reader handles.
///
/// This is the form nearly every message carries, read without building tokens, so the result
/// and the empty issue list match [`parse_general`] by construction: the calendar and range
/// checks are the ones the general path runs, and any issue they raise sends the value there.
fn clean_instant(value: &[u8]) -> Option<Instant> {
    let mut issues = Vec::new();
    let fields = clean_fields(value, &mut issues)?;
    let instant = instant_of(&mut issues, &fields);
    issues.is_empty().then_some(instant?)
}

/// The fields of a value in the clean form, with the issues their range checks raise.
fn clean_fields(value: &[u8], issues: &mut Vec<Issue>) -> Option<Fields> {
    let mut rest = value;
    let weekday = if rest.first()?.is_ascii_alphabetic() {
        Some(clean_weekday(&mut rest)?)
    } else {
        None
    };
    let (day, month, year) = clean_date(&mut rest, issues)?;
    let (time, zone_minutes) = clean_clock(rest, issues)?;
    Some(Fields {
        day,
        month,
        time,
        weekday,
        year,
        zone_minutes,
    })
}

/// Reads `D[D] Mon YYYY `.
fn clean_date(rest: &mut &[u8], issues: &mut Vec<Issue>) -> Option<(Number, i16, i16)> {
    let day_width = if rest.get(1) == Some(&b' ') { 1 } else { 2 };
    let day = day_of(issues, clean_number(rest, day_width, b' ')?)?;
    let month = clean_name(rest, &MONTHS, 1, b' ')?;
    let year = widen_year(issues, clean_number(rest, 4, b' ')?)?;
    Some((day, month, year))
}

/// Reads `HH:MM[:SS] +ZZZZ` through the end of the value.
fn clean_clock(mut rest: &[u8], issues: &mut Vec<Issue>) -> Option<(Time, i16)> {
    let hour = ranged(issues, clean_number(&mut rest, 2, b':')?, 0..=23)?;
    let (minute, second) = clean_minute(&mut rest, issues)?;
    let zone_minutes = clean_zone(rest, issues)?;
    Some((
        Time {
            hour,
            minute,
            second,
        },
        zone_minutes,
    ))
}

/// The index, plus `first`, of the entry of `table` that the next three bytes spell in any case.
fn clean_name(rest: &mut &[u8], table: &[&str], first: i16, end: u8) -> Option<i16> {
    let name = take(rest, 3, end)?;
    table
        .iter()
        .zip(first..)
        .find(|(entry, _)| entry.as_bytes().eq_ignore_ascii_case(name))
        .map(|(_, index)| index)
}

/// Reads `width` digits and the `end` byte after them.
fn clean_number(rest: &mut &[u8], width: usize, end: u8) -> Option<Number> {
    number_of(take(rest, width, end)?, 0)
}

/// Reads `MM ` or `MM:SS `.
fn clean_minute(rest: &mut &[u8], issues: &mut Vec<Issue>) -> Option<(i16, i16)> {
    let minute = ranged(issues, number_of(rest.get(..2)?, 0)?, 0..=59)?;
    let (&separator, tail) = rest.get(2..)?.split_first()?;
    *rest = tail;
    match separator {
        b' ' => Some((minute, 0)),
        b':' => Some((minute, seconds(issues, clean_number(rest, 2, b' ')?)?)),
        _ => None,
    }
}

/// Reads `Www, `.
fn clean_weekday(rest: &mut &[u8]) -> Option<Weekday> {
    let value = clean_name(rest, &WEEKDAYS, 0, b',')?;
    *rest = rest.strip_prefix(b" ")?;
    Some(Weekday { offset: 0, value })
}

/// Reads the whole of `rest` as `+HHMM` or `-HHMM`.
fn clean_zone(rest: &[u8], issues: &mut Vec<Issue>) -> Option<i16> {
    let (&sign, digits) = rest.split_first().filter(|(_, digits)| digits.len() == 4)?;
    let (hours, minutes) = digits.split_at(2);
    let total = zone_magnitude(issues, number_of(hours, 0)?, Some(number_of(minutes, 0)?))?;
    Some(Sign::of(sign)?.apply(total))
}

/// Splits `width` bytes and then the `end` byte off the front of `rest`.
fn take<'src>(rest: &mut &'src [u8], width: usize, end: u8) -> Option<&'src [u8]> {
    let (head, tail) = rest.split_at_checked(width)?;
    *rest = tail.strip_prefix(&[end])?;
    Some(head)
}

/// Days since 1970-01-01 of a proleptic Gregorian date, by Howard Hinnant's `days_from_civil`;
/// `None` when a step overflows. The day is not checked against its month.
#[must_use]
pub fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    let shifted_year = year.checked_sub(i64::from(month <= 2))?;
    let era = shifted_year.div_euclid(400);
    let year_of_era = shifted_year.rem_euclid(400);
    let shifted_month = month.checked_add(9)?.rem_euclid(12);
    let day_of_year = shifted_month
        .checked_mul(153)?
        .checked_add(2)?
        .div_euclid(5)
        .checked_add(day)?
        .checked_sub(1)?;
    let day_of_era = year_of_era
        .checked_mul(365)?
        .checked_add(year_of_era.div_euclid(4))?
        .checked_sub(year_of_era.div_euclid(100))?
        .checked_add(day_of_year)?;
    era.checked_mul(146_097)?
        .checked_add(day_of_era)?
        .checked_sub(719_468)
}

/// The proleptic Gregorian `(year, month, day)` of `days` since 1970-01-01, by Howard Hinnant's
/// `civil_from_days`.
///
/// # Panics
///
/// When `days` exceeds `i64::MAX - 719_468`, because the shift to the era origin overflows.
/// Every value below it, down to `i64::MIN`, converts.
#[must_use]
#[expect(
    clippy::disallowed_methods,
    reason = "`days` comes from an i64 count of seconds, so it is below 2^47 and no step here \
              comes near 2^63"
)]
pub fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days.strict_add(719_468);
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era = day_of_era
        .strict_sub(day_of_era.div_euclid(1460))
        .strict_add(day_of_era.div_euclid(36_524))
        .strict_sub(day_of_era.div_euclid(146_096))
        .div_euclid(365);
    let year_days = year_of_era
        .strict_mul(365)
        .strict_add(year_of_era.div_euclid(4))
        .strict_sub(year_of_era.div_euclid(100));
    let day_of_year = day_of_era.strict_sub(year_days);
    let shifted_month = day_of_year.strict_mul(5).strict_add(2).div_euclid(153);
    let day = day_of_year
        .strict_sub(shifted_month.strict_mul(153).strict_add(2).div_euclid(5))
        .strict_add(1);
    let month = if shifted_month < 10 {
        shifted_month.strict_add(3)
    } else {
        shifted_month.strict_sub(9)
    };
    let year = year_of_era
        .strict_add(era.strict_mul(400))
        .strict_add(i64::from(month <= 2));
    (year, month, day)
}

/// `seconds` since the Unix epoch as an RFC 3339 UTC string, to the second.
#[must_use]
pub fn rfc3339(seconds: i64) -> String {
    let mut text = date_and_time(seconds);
    text.push('Z');
    text
}

/// `micros` since the Unix epoch as an RFC 3339 UTC string, with fractional seconds only when
/// non-zero.
#[must_use]
pub fn rfc3339_micros(micros: i64) -> String {
    let mut text = date_and_time(micros.div_euclid(MICROS_PER_SECOND));
    let fraction = micros.rem_euclid(MICROS_PER_SECOND);
    if fraction != 0 {
        let digits = format!("{fraction:06}");
        text.push('.');
        text.push_str(digits.trim_end_matches('0'));
    }
    text.push('Z');
    text
}

/// `seconds` since the Unix epoch as `YYYY-MM-DDTHH:MM:SS`, with no zone designator.
fn date_and_time(seconds: i64) -> String {
    let (year, month, day) = civil_from_days(seconds.div_euclid(DAY_SECONDS));
    let rest = seconds.rem_euclid(DAY_SECONDS);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}",
        rest.div_euclid(3600),
        rest.rem_euclid(3600).div_euclid(60),
        rest.rem_euclid(60)
    )
}

/// The number of days in `month` (1 to 12) of `year`.
const fn days_in_month(year: i16, month: i16) -> i16 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// The instant `fields` name, after checking the day against its month and the weekday
/// against the date.
fn instant_of(issues: &mut Vec<Issue>, fields: &Fields) -> Option<Instant> {
    if fields.day.value > days_in_month(fields.year, fields.month) {
        issues.push(Issue::new(IssueKind::OutOfRange, fields.day.offset));
        return None;
    }
    let days = days_from_civil(
        i64::from(fields.year),
        i64::from(fields.month),
        i64::from(fields.day.value),
    )?;
    check_weekday(issues, fields.weekday, days);
    Some(Instant {
        offset_minutes: fields.zone_minutes,
        unix_seconds: unix_seconds(days, fields.time, fields.zone_minutes),
    })
}

/// Whether `year` has a 29 February.
const fn is_leap(year: i16) -> bool {
    year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0)
}

/// The index of the entry of `table` that `text` names, plus `first`; `text` may be a longer
/// spelling such as `Sept` or `Tuesday`.
fn name_index(table: &[&str], text: &str, first: i16) -> Option<i16> {
    let long_enough = (3..=9).contains(&text.len());
    let prefix = text.get(..3).filter(|_| long_enough)?;
    if !text.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return None;
    }
    table
        .iter()
        .zip(first..)
        .find(|(name, _)| name.eq_ignore_ascii_case(prefix))
        .map(|(_, index)| index)
}

/// Reads `bytes` as one to four ASCII digits starting at `offset` in the value.
fn number_of(bytes: &[u8], offset: usize) -> Option<Number> {
    if bytes.is_empty() || bytes.len() > 4 || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let value = bytes.iter().fold(0_i16, |sum, byte| {
        sum.saturating_mul(10)
            .saturating_add(i16::from(byte.saturating_sub(b'0')))
    });
    Some(Number {
        digits: bytes.len(),
        offset,
        value,
    })
}

/// Parses a `Date` header value into an [`Instant`].
///
/// Accepts RFC 5322 dates with the obsolete forms of its section 4.3 (two- and three-digit
/// years, named and military zones, a missing weekday or seconds, comments and folding),
/// asctime (`Mon Jan  1 12:00:00 2024`) and ISO 8601 / RFC 3339 (`2024-01-01T12:00:00Z`).
/// Each guess is an issue at the byte offset it concerns: [`IssueKind::AssumedZone`],
/// [`IssueKind::WeekdayMismatch`], [`IssueKind::WidenedYear`], [`IssueKind::OutOfRange`] for
/// a clamped leap second, and [`IssueKind::TrailingText`] for ignored text. A value that
/// cannot be read, or has a field out of range, gives `None` and an issue; empty input and
/// arbitrary bytes never panic. Input past [`crate::MAX_HEADER_BYTES`] is dropped before either
/// reading and reported as one [`IssueKind::CapExceeded`] issue at the cap.
#[must_use]
pub fn parse_date(value: &[u8]) -> Parsed<Option<Instant>> {
    if let Some(instant) = clean_instant(value) {
        return Parsed::new(Some(instant), Vec::new());
    }
    parse_general(value)
}

/// [`parse_date`] without the clean-form shortcut: tokens or bytes, with every issue reported.
fn parse_general(value: &[u8]) -> Parsed<Option<Instant>> {
    let (head, cut) = bound(value);
    let mut raw = Raw::new(head);
    if raw.looks_iso() {
        let instant = raw.instant();
        raw.issues.extend(cut);
        return Parsed::new(instant, raw.issues);
    }
    let (tokens, issues) = tokenize(head).into_parts();
    let mut cursor = Cursor::new(&tokens, issues, head.len());
    let instant = cursor.instant();
    cursor.issues.extend(cut);
    Parsed::new(instant, cursor.issues)
}

/// `number`'s value when it lies in `range`; otherwise reports [`IssueKind::OutOfRange`].
fn ranged(issues: &mut Vec<Issue>, number: Number, range: RangeInclusive<i16>) -> Option<i16> {
    if range.contains(&number.value) {
        return Some(number.value);
    }
    issues.push(Issue::new(IssueKind::OutOfRange, number.offset));
    None
}

/// The second `number` names, with a leap second (60) clamped to 59 and reported.
fn seconds(issues: &mut Vec<Issue>, number: Number) -> Option<i16> {
    let value = ranged(issues, number, 0..=60)?;
    if value < 60 {
        return Some(value);
    }
    issues.push(Issue::new(IssueKind::OutOfRange, number.offset));
    Some(59)
}

/// UTC seconds since the epoch for the date `days` after it, at `time` in `zone_minutes`.
#[expect(
    clippy::arithmetic_side_effects,
    reason = "days is below 3 * 10^6 and the rest is below 10^5, so the sum fits in i64"
)]
fn unix_seconds(days: i64, time: Time, zone_minutes: i16) -> i64 {
    let local = i64::from(time.hour) * 3600 + i64::from(time.minute) * 60 + i64::from(time.second);
    days * DAY_SECONDS + local - i64::from(zone_minutes) * 60
}

/// The four-digit year for `number`, widening two and three digit years and reporting it.
fn widen_year(issues: &mut Vec<Issue>, number: Number) -> Option<i16> {
    let base = match (number.digits, number.value) {
        (4, _) => return Some(number.value),
        (2, 0..=49) => 2000_i16,
        (2 | 3, _) => 1900_i16,
        _ => {
            issues.push(Issue::new(IssueKind::UnparsableDate, number.offset));
            return None;
        },
    };
    issues.push(Issue::new(IssueKind::WidenedYear, number.offset));
    Some(base.saturating_add(number.value))
}

/// Unsigned minutes of a written zone, rejecting hours past 23 and minutes past 59.
fn zone_magnitude(issues: &mut Vec<Issue>, hours: Number, minutes: Option<Number>) -> Option<i16> {
    let whole_hours = ranged(issues, hours, 0..=23)?;
    let extra = match minutes {
        Some(number) => ranged(issues, number, 0..=59)?,
        None => 0,
    };
    Some(whole_hours.saturating_mul(60).saturating_add(extra))
}

#[cfg(test)]
mod tests {
    use std::iter::repeat_with;

    use proptest::option;
    use proptest::prelude::*;

    use super::{
        Instant, civil_from_days, clean_instant, parse_date, parse_general, rfc3339, rfc3339_micros,
    };
    use crate::caps::{Cap, MAX_HEADER_BYTES};
    use crate::issue::{Issue, IssueKind};

    /// 2024-01-01T12:00:00Z.
    const NOON: i64 = 1_704_110_400;

    #[test]
    fn civil_from_days_converts_up_to_its_documented_bound() {
        assert!(
            civil_from_days(i64::MAX - 719_468).0 > 0,
            "the largest day count converts to a year"
        );
        assert!(
            civil_from_days(i64::MIN).0 < 0,
            "the smallest day count converts to a year"
        );
    }

    #[test]
    #[should_panic(expected = "overflow")]
    fn civil_from_days_panics_one_day_past_its_documented_bound() {
        assert_eq!(
            civil_from_days(i64::MAX - 719_467),
            (0, 0, 0),
            "the shift overflows before any date is produced"
        );
    }

    fn parse(text: &str) -> (Option<Instant>, Vec<Issue>) {
        parse_date(text.as_bytes()).into_parts()
    }

    fn kinds(issues: &[Issue]) -> Vec<(IssueKind, usize)> {
        issues
            .iter()
            .map(|issue| (issue.kind(), issue.offset()))
            .collect()
    }

    fn seconds_and_offset(text: &str) -> (i64, i16) {
        let (instant, issues) = parse(text);
        let found = instant.expect("the date is readable");
        assert!(issues.is_empty(), "{text:?} is clean, got {issues:?}");
        (found.unix_seconds(), found.offset_minutes())
    }

    #[test]
    fn an_iso_value_one_byte_over_the_header_cap_is_cut_and_reported_at_the_cap() {
        let input = format!("2024-01-01T12:00:00Z{}", " ".repeat(MAX_HEADER_BYTES - 19));
        let (instant, issues) = parse(&input);
        assert_eq!(
            instant.map(|found| found.unix_seconds()),
            Some(NOON),
            "the date before the cut is read"
        );
        assert_eq!(
            kinds(&issues),
            [(
                IssueKind::CapExceeded {
                    cap: Cap::HeaderBytes
                },
                MAX_HEADER_BYTES
            )],
            "one issue at the cap"
        );
    }

    #[test]
    fn the_dates_the_index_extractor_reads_give_the_same_instants() {
        let cases = [
            // FOLDED, LOWER, NZ, KIRITIMATI and CRLF of crates/mboxturbo/src/index/date.rs.
            ("Mon, 01 Jan 2024\n 12:00:00 +0000", NOON, 0),
            (" Mon, 01 Jan 2024 12:00:00 -0500", NOON + 18_000, -300),
            (
                " Mon, 01 Jan 2024 12:00:00 +1300 (NZDT)",
                NOON - 46_800,
                780,
            ),
            (" Mon, 01 Jan 2024 12:00:00 +1400", 1_704_060_000, 840),
            (" Mon, 01 Jan 2024 12:00:00 +0100\r", NOON - 3600, 60),
            ("Mon, 01 Jan 2024\r\n 12:00:00 +0000", NOON, 0),
            (" Tue, 02 Jan 2024 12:00:00 +0000", 1_704_196_800, 0),
        ];
        for (text, seconds, offset) in cases {
            assert_eq!(
                seconds_and_offset(text),
                (seconds, offset),
                "{text:?} matches mail-parser's reading"
            );
        }
    }

    #[test]
    fn the_epoch_and_leap_day_land_on_the_right_second() {
        assert_eq!(
            seconds_and_offset("Thu, 01 Jan 1970 00:00:00 +0000").0,
            0,
            "the epoch"
        );
        assert_eq!(
            seconds_and_offset("Thu, 29 Feb 2024 23:59:59 +0000").0,
            1_709_251_199,
            "the last second of a leap day"
        );
        assert_eq!(
            seconds_and_offset("Wed, 31 Dec 1969 23:59:59 +0000").0,
            -1,
            "one second before the epoch"
        );
    }

    #[test]
    fn named_zones_map_to_their_rfc_offsets() {
        let zones = [
            ("UT", 0),
            ("GMT", 0),
            ("EST", -300),
            ("EDT", -240),
            ("CST", -360),
            ("CDT", -300),
            ("MST", -420),
            ("MDT", -360),
            ("PST", -480),
            ("PDT", -420),
            ("pst", -480),
            ("Z", 0),
        ];
        for (name, minutes) in zones {
            let text = format!("Mon, 01 Jan 2024 12:00:00 {name}");
            assert_eq!(
                seconds_and_offset(&text),
                (NOON - i64::from(minutes) * 60, minutes),
                "{name} is {minutes} minutes"
            );
        }
    }

    #[test]
    fn military_unknown_and_missing_zones_are_assumed_utc_and_reported() {
        let text = "Mon, 01 Jan 2024 12:00:00";
        let cases = [
            ("Mon, 01 Jan 2024 12:00:00 A", 26),
            ("Mon, 01 Jan 2024 12:00:00 CEST", 26),
            (text, text.len()),
        ];
        for (value, offset) in cases {
            let (instant, issues) = parse(value);
            let found = instant.expect("a guessed zone still gives an instant");
            assert_eq!(
                (found.unix_seconds(), found.offset_minutes()),
                (NOON, 0),
                "{value:?} reads as UTC"
            );
            assert_eq!(
                kinds(&issues),
                vec![(IssueKind::AssumedZone, offset)],
                "{value:?} reports the assumed zone where it was missing or wrong"
            );
        }
    }

    #[test]
    fn two_and_three_digit_years_are_widened_and_reported() {
        let cases = [
            ("01 Jan 24 12:00:00 +0000", 2024_i64, 7),
            ("01 Jan 49 12:00:00 +0000", 2049, 7),
            ("01 Jan 70 12:00:00 +0000", 1970, 7),
            ("01 Jan 124 12:00:00 +0000", 2024, 7),
        ];
        for (text, year, offset) in cases {
            let (instant, issues) = parse(text);
            let found = instant.expect("a widened year still gives an instant");
            let (expected, _) = seconds_and_offset(&format!("01 Jan {year} 12:00:00 +0000"));
            assert_eq!(found.unix_seconds(), expected, "{text:?} reads as {year}");
            assert_eq!(
                kinds(&issues),
                vec![(IssueKind::WidenedYear, offset)],
                "{text:?} reports the widened year"
            );
        }
    }

    #[test]
    fn a_wrong_weekday_is_reported_and_a_missing_one_is_not() {
        let (instant, issues) = parse("Tue, 01 Jan 2024 12:00:00 +0000");
        assert_eq!(
            instant.map(|found| found.unix_seconds()),
            Some(NOON),
            "the calendar date wins over the weekday"
        );
        assert_eq!(
            kinds(&issues),
            vec![(IssueKind::WeekdayMismatch, 0)],
            "Monday was written as Tuesday"
        );
        assert_eq!(
            seconds_and_offset("1 Jan 2024 12:00:00 +0000").0,
            NOON,
            "no weekday and no issue"
        );
    }

    #[test]
    fn obsolete_layouts_parse_cleanly() {
        let cases = [
            "Mon, 01 Jan 2024 12:00 +0000",
            "Mon 01 Jan 2024 12:00:00 +0000",
            "  Mon,   01   Jan   2024   12:00:00   +0000  ",
            "Mon, (hello (nested)) 01 Jan 2024 12:00:00 +0000 (UTC)",
            "Mon,\r\n 01 Jan\r\n\t2024 12:00:00 +0000",
            "MON, 1 JAN 2024 12 : 00 : 00 GMT",
            "Monday, 01 January 2024 12:00:00 +0000",
        ];
        for text in cases {
            assert_eq!(
                seconds_and_offset(text).0,
                NOON,
                "{text:?} reads as noon on 1 January 2024"
            );
        }
    }

    #[test]
    fn asctime_dates_parse_and_assume_utc() {
        let (instant, issues) = parse("Mon Jan  1 12:00:00 2024");
        assert_eq!(
            instant.map(|found| (found.unix_seconds(), found.offset_minutes())),
            Some((NOON, 0)),
            "asctime has no zone"
        );
        assert_eq!(
            kinds(&issues),
            vec![(IssueKind::AssumedZone, 24)],
            "the missing zone is reported at the end"
        );
        assert_eq!(
            seconds_and_offset("Mon Jan  1 12:00:00 2024 +0100").0,
            NOON - 3600,
            "a zone after the year is honoured"
        );
    }

    #[test]
    fn iso_8601_and_rfc_3339_dates_parse() {
        let cases = [
            ("2024-01-01T12:00:00Z", NOON, 0),
            ("2024-01-01t12:00:00z", NOON, 0),
            ("2024-01-01T12:00:00+00:00", NOON, 0),
            ("2024-01-01T13:00:00+01:00", NOON, 60),
            ("2024-01-01T07:00:00-0500", NOON, -300),
            ("2024-01-01 12:00:00.250Z", NOON, 0),
            ("2024-01-01T12:00:00.5+00", NOON, 0),
            ("  2024-01-01T12:00:00Z  ", NOON, 0),
        ];
        for (text, seconds, offset) in cases {
            assert_eq!(
                seconds_and_offset(text),
                (seconds, offset),
                "{text:?} is noon UTC"
            );
        }
        let (instant, issues) = parse("2024-01-01");
        assert_eq!(
            instant.map(|found| found.unix_seconds()),
            Some(1_704_067_200),
            "a date alone is midnight"
        );
        assert_eq!(
            kinds(&issues),
            vec![(IssueKind::AssumedZone, 10)],
            "and its zone is assumed"
        );
    }

    #[test]
    fn out_of_range_fields_are_rejected() {
        let rejected = [
            ("Mon, 32 Jan 2024 12:00:00 +0000", 5),
            ("Thu, 30 Feb 2024 12:00:00 +0000", 5),
            ("Mon, 01 Jan 2024 24:00:00 +0000", 17),
            ("Mon, 01 Jan 2024 12:60:00 +0000", 20),
            ("Mon, 01 Jan 2024 12:00:61 +0000", 23),
            ("Mon, 01 Jan 2024 12:00:00 +2400", 27),
            ("Mon, 01 Jan 2024 12:00:00 +0060", 29),
            ("2024-13-01T12:00:00Z", 5),
            ("2024-02-30T12:00:00Z", 8),
        ];
        for (text, offset) in rejected {
            let (instant, issues) = parse(text);
            assert_eq!(instant, None, "{text:?} has no instant");
            assert_eq!(
                kinds(&issues),
                vec![(IssueKind::OutOfRange, offset)],
                "{text:?} reports the field"
            );
        }
    }

    #[test]
    fn a_leap_second_is_clamped_to_59_and_reported() {
        let (instant, issues) = parse("Mon, 01 Jan 2024 12:00:60 +0000");
        assert_eq!(
            instant.map(|found| found.unix_seconds()),
            Some(NOON + 59),
            "a leap second becomes 59"
        );
        assert_eq!(
            kinds(&issues),
            vec![(IssueKind::OutOfRange, 23)],
            "and is reported"
        );
    }

    #[test]
    fn text_after_the_date_is_ignored_and_reported() {
        let (instant, issues) = parse("Mon, 01 Jan 2024 12:00:00 +0000 extra");
        assert_eq!(
            instant.map(|found| found.unix_seconds()),
            Some(NOON),
            "the date itself is intact"
        );
        assert_eq!(
            kinds(&issues),
            vec![(IssueKind::TrailingText, 32)],
            "the extra word is reported"
        );
    }

    #[test]
    fn unreadable_values_give_no_instant_and_an_issue() {
        let cases = [
            "",
            "   ",
            "not a date",
            "Mon, 01 Foo 2024 12:00:00 +0000",
            "Mon, 01 Jan 2024",
            "Mon, 01 Jan 12345 12:00:00 +0000",
            "(only a comment)",
            "2024-01",
        ];
        for text in cases {
            let (instant, issues) = parse(text);
            assert_eq!(instant, None, "{text:?} has no instant");
            assert!(
                issues
                    .iter()
                    .any(|issue| issue.kind() == IssueKind::UnparsableDate),
                "{text:?} reports why, got {issues:?}"
            );
        }
    }

    #[test]
    fn every_single_byte_and_repeated_byte_is_no_date() {
        for byte in 0..=u8::MAX {
            assert_eq!(parse_date(&[byte]).value(), &None, "one byte is no date");
            assert_eq!(
                parse_date(&[byte; 64]).value(),
                &None,
                "repeated bytes are no date"
            );
        }
    }

    #[test]
    fn pseudo_random_bytes_are_no_date() {
        let mut state = 0x9E37_79B9_u32;
        let garbage: Vec<u8> = repeat_with(|| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            state.to_le_bytes()[2]
        })
        .take(4096)
        .collect();
        assert_eq!(
            parse_date(&garbage).value(),
            &None,
            "random bytes are not a date"
        );
    }

    #[test]
    fn a_one_mebibyte_value_is_handled_whatever_it_holds() {
        for filler in [&b"("[..], b"a ", b" ", b"9", b"\\", b"2024-"] {
            let huge: Vec<u8> = filler.iter().copied().cycle().take(1 << 20).collect();
            let parsed = parse_date(&huge);
            assert_eq!(
                parsed.value(),
                &None,
                "a 1 MiB value of {filler:?} is no date"
            );
            assert!(
                !parsed.issues().is_empty(),
                "a 1 MiB value of {filler:?} reports why"
            );
        }
        let mut padded = b"Mon, 01 Jan 2024 12:00:00 +0000".to_vec();
        padded.resize(1 << 20, b' ');
        assert_eq!(
            parse_date(&padded)
                .value()
                .map(|found| found.unix_seconds()),
            Some(NOON),
            "a date followed by a mebibyte of spaces still parses"
        );
    }

    /// An RFC 5322 date built from independently varied fields, so most draws are near the clean
    /// form and the rest break it in one place: a wrong weekday, an out-of-range field, a short
    /// or long field, another separator or trailing text.
    fn near_clean_dates() -> impl Strategy<Value = String> {
        (
            prop_oneof![
                Just(String::new()),
                "(Mon|Tue|Wed|Thu|Fri|Sat|Sun|mon|TUE|Tues|Xyz), ",
                "(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ",
            ],
            "[0-9]{1,3}",
            "(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec|feb|DEC|Sept|Xyz)",
            "[0-9]{1,5}",
            "[0-9]{1,3}:[0-9]{1,3}(:[0-9]{1,3})?",
            "[-+][0-9]{2,5}|GMT|Z|[-+][0-9]{2}:[0-9]{2}",
            "( |  |\t|\\(c\\) |x)?",
        )
            .prop_map(|(weekday, day, month, year, time, zone, tail)| {
                format!("{weekday}{day} {month} {year} {time} {zone}{tail}")
            })
    }

    #[test]
    fn a_dated_rfc_5322_value_with_matching_weekday_takes_the_shortcut() {
        for text in [
            "Tue, 03 Feb 2015 10:14:01 +0000",
            "Tue, 3 Feb 2015 10:14 -0530",
        ] {
            assert_eq!(
                clean_instant(text.as_bytes()),
                *parse_general(text.as_bytes()).value(),
                "the shortcut reads {text:?} as the general reader does"
            );
            assert!(
                clean_instant(text.as_bytes()).is_some(),
                "{text:?} is in the clean form"
            );
        }
        assert_eq!(
            clean_instant(b"Wed, 03 Feb 2015 10:14:01 +0000"),
            None,
            "a wrong weekday is an issue, so it goes to the general reader"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(5_000))]

        #[test]
        fn the_clean_form_shortcut_gives_the_general_readers_result(text in near_clean_dates()) {
            prop_assert_eq!(
                parse_date(text.as_bytes()),
                parse_general(text.as_bytes()),
                "the shortcut must not change the instant or the issues of {:?}",
                text
            );
        }

        #[test]
        fn a_value_the_general_reader_accepts_without_issues_in_the_clean_form_takes_the_shortcut(
            day in 1_u8..=28,
            month in "(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)",
            year in 1000_u16..=9999,
            time in (0_u8..24, 0_u8..60, option::of(0_u8..60)),
            zone in (prop_oneof![Just('+'), Just('-')], 0_u8..24, 0_u8..60),
        ) {
            let seconds = time.2.map_or_else(String::new, |second| format!(":{second:02}"));
            let text = format!(
                "{day} {month} {year} {:02}:{:02}{seconds} {}{:02}{:02}",
                time.0, time.1, zone.0, zone.1, zone.2
            );
            let general = parse_general(text.as_bytes());
            prop_assert!(general.issues().is_empty(), "{:?} is a clean date", text);
            prop_assert_eq!(
                clean_instant(text.as_bytes()),
                *general.value(),
                "the shortcut reads {:?} as the general reader does",
                text
            );
        }
    }

    #[test]
    fn seconds_since_the_epoch_render_as_rfc_3339_utc() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z", "the epoch");
        assert_eq!(
            rfc3339(1_704_096_000),
            "2024-01-01T08:00:00Z",
            "a 2024 date"
        );
        assert_eq!(
            rfc3339(1_709_164_799),
            "2024-02-28T23:59:59Z",
            "before a leap day"
        );
        assert_eq!(rfc3339(1_709_164_800), "2024-02-29T00:00:00Z", "a leap day");
        assert_eq!(
            rfc3339(-1),
            "1969-12-31T23:59:59Z",
            "one second before the epoch"
        );
    }

    #[test]
    fn fractional_seconds_appear_only_when_non_zero_without_trailing_zeros() {
        assert_eq!(
            rfc3339_micros(1_704_096_000_000_000),
            "2024-01-01T08:00:00Z",
            "whole seconds carry no fraction"
        );
        assert_eq!(
            rfc3339_micros(1_704_096_000_500_000),
            "2024-01-01T08:00:00.5Z",
            "trailing zeros of the fraction are trimmed"
        );
        assert_eq!(
            rfc3339_micros(1_704_096_000_000_001),
            "2024-01-01T08:00:00.000001Z",
            "leading zeros of the fraction are kept"
        );
        assert_eq!(
            rfc3339_micros(-500_000),
            "1969-12-31T23:59:59.5Z",
            "a time before the epoch rounds down to the second"
        );
    }
}
