//! The `info` subcommand: reports a mailbox's message count and date span from its index.

use std::io::{self, Write as _};
use std::path::PathBuf;

use clap::Args;
use mboxturbo::rfc3339;

use crate::events::{self, Info, Report};
use crate::failure::{self, Failure};
use crate::open::open;
use crate::progress::{self, Feedback};

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
    let mailbox = open(&args.mailbox, args.index.as_deref())?;
    progress::note_origin(feedback, mailbox.index_origin()).map_err(failure::stderr_failure)?;
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
    .map_err(failure::stdout_failure)
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
