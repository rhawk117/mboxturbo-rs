//! Parses the `WHEN` of `--since` and `--until` into unix seconds.
//!
//! A `WHEN` is an RFC 3339 timestamp with an offset, such as `2024-01-01T09:30:00+02:00`, with
//! optional fractional seconds, or a plain date `YYYY-MM-DD` read as midnight UTC. A fractional
//! second rounds up to the next whole second, as the Python `select` bounds do.

use std::fmt;

use mboxturbo::{DateBounds, days_from_civil};

/// Seconds in a day.
const SECONDS_PER_DAY: i64 = 86_400;

/// A `--since` or `--until` value that is neither a date nor an RFC 3339 timestamp.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct DateError {
    /// The flag that carried the value, with its dashes.
    flag: &'static str,
    /// The rejected text.
    value: String,
}

impl fmt::Display for DateError {
    #[expect(
        clippy::renamed_function_params,
        reason = "the trait calls it `f`, a one-letter name the min_ident_chars lint bans"
    )]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid {} `{}`: expected an RFC 3339 timestamp with an offset such as \
             2024-01-01T00:00:00Z, or a date YYYY-MM-DD",
            self.flag, self.value
        )
    }
}

/// The bounds named by the `--since` and `--until` values.
///
/// # Errors
///
/// A [`DateError`] naming the flag and value of the first one that does not parse.
pub(crate) fn bounds(since: Option<&str>, until: Option<&str>) -> Result<DateBounds, DateError> {
    Ok(DateBounds::new(
        since.map(|text| parse("--since", text)).transpose()?,
        until.map(|text| parse("--until", text)).transpose()?,
    ))
}

/// Unix seconds of `text`, the value of `flag`.
fn parse(flag: &'static str, text: &str) -> Result<i64, DateError> {
    seconds(text).ok_or_else(|| DateError {
        flag,
        value: text.to_owned(),
    })
}

/// Unix seconds of a plain date or an RFC 3339 timestamp; `None` when `text` is neither.
fn seconds(text: &str) -> Option<i64> {
    let Some((date, rest)) = text.split_once(['T', 't']) else {
        return days(text)?.checked_mul(SECONDS_PER_DAY);
    };
    let (clock, offset) = split_zone(rest)?;
    days(date)?
        .checked_mul(SECONDS_PER_DAY)?
        .checked_add(clock_seconds(clock)?)?
        .checked_sub(offset)
}

/// Splits `rest`, the part of a timestamp after the `T`, into its clock and its offset from UTC
/// in seconds.
fn split_zone(rest: &str) -> Option<(&str, i64)> {
    if let Some(clock) = rest.strip_suffix(['Z', 'z']) {
        return Some((clock, 0));
    }
    let (clock, zone) = rest.split_at_checked(rest.rfind(['+', '-'])?)?;
    Some((clock, offset(zone)?))
}

/// Seconds east of UTC of a `+HH:MM` or `-HH:MM` offset.
fn offset(zone: &str) -> Option<i64> {
    let (sign, digits) = if let Some(digits) = zone.strip_prefix('+') {
        (1, digits)
    } else {
        (-1, zone.strip_prefix('-')?)
    };
    let (hours, minutes) = digits.split_once(':')?;
    bounded(hours, 23)?
        .checked_mul(3600)?
        .checked_add(bounded(minutes, 59)?.checked_mul(60)?)?
        .checked_mul(sign)
}

/// Seconds since midnight of `HH:MM:SS` with optional fractional seconds, rounded up.
fn clock_seconds(clock: &str) -> Option<i64> {
    let (whole, fraction) = clock
        .split_once('.')
        .map_or((clock, None), |(whole, fraction)| (whole, Some(fraction)));
    let mut parts = whole.split(':');
    let hours = bounded(parts.next()?, 23)?;
    let minutes = bounded(parts.next()?, 59)?;
    let seconds = bounded(parts.next()?, 59)?;
    if parts.next().is_some() {
        return None;
    }
    hours
        .checked_mul(3600)?
        .checked_add(minutes.checked_mul(60)?)?
        .checked_add(seconds)?
        .checked_add(rounding(fraction)?)
}

/// One second when `fraction`, the digits after the decimal point, is not zero, otherwise none;
/// `None` when it is not digits.
fn rounding(fraction: Option<&str>) -> Option<i64> {
    let Some(digits) = fraction else {
        return Some(0);
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(i64::from(digits.bytes().any(|byte| byte != b'0')))
}

/// Days since 1970-01-01 of a `YYYY-MM-DD` date; `None` when it is not a real calendar date.
fn days(date: &str) -> Option<i64> {
    let mut parts = date.split('-');
    let year = digits(parts.next()?, 4)?;
    let month = digits(parts.next()?, 2)?;
    let day = digits(parts.next()?, 2)?;
    if parts.next().is_some() || !(1..=month_length(year, month)?).contains(&day) {
        return None;
    }
    days_from_civil(year, month, day)
}

/// How many days `month` of `year` has; `None` for a month outside 1 to 12.
const fn month_length(year: i64, month: i64) -> Option<i64> {
    let leap = year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0);
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 => Some(if leap { 29 } else { 28 }),
        _ => None,
    }
}

/// `text` as a number when it is exactly `width` ASCII digits.
fn digits(text: &str, width: usize) -> Option<i64> {
    if text.len() != width {
        return None;
    }
    text.chars().try_fold(0_i64, |number, digit| {
        number
            .checked_mul(10)?
            .checked_add(i64::from(digit.to_digit(10)?))
    })
}

/// Two ASCII digits as a number no greater than `max`.
fn bounded(text: &str, max: i64) -> Option<i64> {
    digits(text, 2).filter(|&number| number <= max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_date_is_midnight_utc() {
        assert_eq!(
            seconds("1970-01-02"),
            Some(86_400),
            "one day after the epoch"
        );
        assert_eq!(seconds("2024-02-29"), Some(1_709_164_800), "a leap day");
    }

    #[test]
    fn an_offset_moves_the_instant_not_the_wall_clock() {
        assert_eq!(
            seconds("2024-01-01T09:30:00+02:00"),
            seconds("2024-01-01T07:30:00Z"),
            "+02:00 is two hours ahead of UTC"
        );
        assert_eq!(
            seconds("2024-01-01T00:00:00-05:30"),
            seconds("2024-01-01T05:30:00Z"),
            "-05:30 is behind UTC"
        );
    }

    #[test]
    fn a_fraction_rounds_up_to_the_next_whole_second() {
        let whole = seconds("2024-01-01T00:00:00Z").expect("a timestamp parses");
        assert_eq!(
            seconds("2024-01-01T00:00:00.000Z"),
            Some(whole),
            "a zero fraction"
        );
        assert_eq!(
            seconds("2024-01-01T00:00:00.000001Z"),
            Some(whole + 1),
            "a microsecond rounds up"
        );
        assert_eq!(
            seconds("2024-01-01T00:00:59.5Z"),
            Some(whole + 60),
            "the rounding carries into the next minute"
        );
    }

    #[test]
    fn text_that_is_not_a_date_or_timestamp_is_rejected() {
        for bad in [
            "",
            "yesterday",
            "2024-1-1",
            "2024-13-01",
            "2023-02-29",
            "2024-04-31",
            "2024-01-01T00:00:00",
            "2024-01-01T24:00:00Z",
            "2024-01-01T00:60:00Z",
            "2024-01-01T00:00Z",
            "2024-01-01T00:00:00.Z",
            "2024-01-01T00:00:00+0200",
            "2024-01-01T00:00:00+24:00",
            "2024-01-01 00:00:00Z",
            "2024-01-01Z",
        ] {
            assert_eq!(seconds(bad), None, "`{bad}` is not a WHEN");
        }
    }

    #[test]
    fn the_error_names_the_flag_and_the_value() {
        let error = bounds(None, Some("soon")).expect_err("`soon` is not a WHEN");
        assert_eq!(
            error,
            DateError {
                flag: "--until",
                value: "soon".to_owned()
            },
            "the second bound is the --until one"
        );
    }
}
