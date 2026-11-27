//! The `show` subcommand: writes one message's stored bytes to standard output.

use std::io::{self, Write as _};
use std::path::PathBuf;

use clap::Args;
use mboxturbo::MboxTurboError;

use crate::events::Report;
use crate::export::{self, Failure};
use crate::progress::{self, Feedback};

/// The arguments of `mboxturbo show`.
#[derive(Debug, Args)]
pub(crate) struct ShowArgs {
    /// Keep the message index in this file instead of beside the mailbox.
    #[arg(long, value_name = "PATH")]
    index: Option<PathBuf>,
    /// The mbox file to read.
    mailbox: PathBuf,
    /// The 0-based position of the message.
    position: usize,
}

/// Runs the `show` subcommand: one lookup after the mailbox is open.
///
/// # Errors
///
/// A [`Failure::Usage`] for `--json`, which cannot share standard output with the message, and a
/// [`Failure::Core`] for a position at or past the message count, for everything opening the
/// mailbox refuses, and for a write to standard output that fails.
pub(crate) fn run(args: &ShowArgs, report: Report, feedback: Feedback) -> Result<(), Failure> {
    if report == Report::Events {
        return Err(Failure::Usage(
            "--json cannot be used with `show`: standard output carries the message".to_owned(),
        ));
    }
    let mailbox = export::open(&args.mailbox, args.index.as_deref())?;
    progress::note_origin(feedback, mailbox.index_origin()).map_err(export::stderr_failure)?;
    let Some(raw) = mailbox.raw(args.position) else {
        return Err(Failure::after_open(Box::new(
            MboxTurboError::PositionOutOfRange {
                position: args.position,
                len: mailbox.len(),
            },
        )));
    };
    io::stdout()
        .lock()
        .write_all(raw)
        .map_err(export::stdout_failure)
}
