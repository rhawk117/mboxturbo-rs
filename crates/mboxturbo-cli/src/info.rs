//! The `info` subcommand: reports a mailbox's message count and date span from its index.

use std::io::{self, Write as _};
use std::path::PathBuf;

use clap::Args;

use crate::events::{self, Info, Report};
use crate::export::{self, Failure};
use crate::progress::{self, Feedback};

/// Seconds in one day.
const SECONDS_PER_DAY: i64 = 86_400;

/// The arguments of `mboxturbo info`.
#[derive(Debug, Args)]
pub(crate) struct InfoArgs {
    /// Keep the message index in this file instead of beside the mailbox.
    #[arg(long, value_name = "PATH")]
    index: Option<PathBuf>,
    /// The mbox file to describe.
    mailbox: PathBuf,
}

/// Runs the `info` subcommand, writing plain lines or one `info` event to standard output.
///
/// # Errors
///
/// A [`Failure::Core`] for everything opening the mailbox refuses and for a write to standard
/// output or standard error that fails.
pub(crate) fn run(args: &InfoArgs, report: Report, feedback: Feedback) -> Result<(), Failure> {
    let mailbox = export::open(&args.mailbox, args.index.as_deref())?;
    progress::note_origin(feedback, mailbox.index_origin()).map_err(export::stderr_failure)?;
    let dates: Vec<i64> = (0..mailbox.len())
        .filter_map(|position| mailbox.date(position))
        .collect();
    let info = Info {
        count: mailbox.len(),
        earliest: dates.iter().min().copied(),
        latest: dates.iter().max().copied(),
        undated: mailbox.len().saturating_sub(dates.len()),
    };
    match report {
        Report::Events => events::info(&info),
        Report::Text => print_text(&info),
    }
    .map_err(export::stdout_failure)
}

/// Writes `info` as plain lines; the span lines are left out when no message has a date.
fn print_text(info: &Info) -> io::Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "messages: {}", info.count)?;
    if let (Some(earliest), Some(latest)) = (info.earliest, info.latest) {
        writeln!(out, "earliest: {}", rfc3339(earliest))?;
        writeln!(out, "latest: {}", rfc3339(latest))?;
    }
    writeln!(out, "undated: {}", info.undated)
}

/// `seconds` since the Unix epoch as an RFC 3339 UTC string.
///
/// The index stores whole seconds, so there is no fractional part to show.
pub(crate) fn rfc3339(seconds: i64) -> String {
    let (year, month, day) = civil_from_days(seconds.div_euclid(SECONDS_PER_DAY));
    let rest = seconds.rem_euclid(SECONDS_PER_DAY);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest.div_euclid(3600),
        rest.rem_euclid(3600).div_euclid(60),
        rest.rem_euclid(60)
    )
}

/// The proleptic Gregorian `(year, month, day)` of `days` since 1970-01-01, by Howard Hinnant's
/// `civil_from_days`.
#[expect(
    clippy::disallowed_methods,
    reason = "`days` comes from an i64 count of seconds, so it is below 2^47 and no step here \
              comes near 2^63"
)]
fn civil_from_days(days: i64) -> (i64, i64, i64) {
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

#[cfg(test)]
mod tests {
    use super::rfc3339;

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
}
