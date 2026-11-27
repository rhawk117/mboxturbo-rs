//! The `mboxturbo` command-line exporter for large mbox files.
//!
//! Every outcome becomes one process exit code, chosen by `exit::error_code`:
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0 | success, including `--help` and `--version` |
//! | 1 | any other failure |
//! | 64 | usage error: bad arguments, or a message position past the last message |
//! | 65 | corrupt or stale index |
//! | 66 | the mailbox does not exist (not found while opening it) |
//! | 73 | the export target exists and `--overwrite` was not given |
//! | 74 | any other I/O error, including a path not found after the mailbox is open |
//! | 129 | interrupted by SIGHUP |
//! | 130 | interrupted by SIGINT (Ctrl-C), or cancelled with no signal |
//! | 143 | interrupted by SIGTERM |
#![expect(
    clippy::redundant_pub_crate,
    reason = "contradicts rustc's unreachable_pub, which is the lint this workspace keeps"
)]
#![expect(
    clippy::multiple_crate_versions,
    reason = "build-time only: arrow's ahash compiles zerocopy-derive on syn 2 while thiserror 2 \
              uses syn 3"
)]

mod dates;
mod events;
mod exit;
mod export;
mod info;
mod progress;
mod select;
mod show;
mod signals;

use std::env;
use std::io::{self, Write as _};
use std::process::ExitCode;

use clap::{ColorChoice, CommandFactory as _, FromArgMatches as _, Parser, Subcommand};

use crate::events::Report;
use crate::export::{ExportArgs, Failure};
use crate::info::InfoArgs;
use crate::progress::{Environment, Feedback};
use crate::show::ShowArgs;

/// Exports large mbox files to analysis-friendly formats.
#[derive(Debug, Parser)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each bool is one command-line flag"
)]
#[command(name = "mboxturbo", version, about)]
struct Cli {
    /// What to do.
    #[command(subcommand)]
    command: Command,
    /// Write a versioned JSON Lines event stream on standard output instead of human text.
    #[arg(long, global = true)]
    json: bool,
    /// Print no progress bar, summary line or index note on standard error; errors still print.
    /// `--json` implies it.
    #[arg(short, long, global = true)]
    quiet: bool,
}

/// The subcommands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Write the selected messages of a mailbox as parquet, eml, mbox, jsonl, csv or arrow.
    Export(ExportArgs),
    /// Print a mailbox's message count, date span and number of undated messages.
    Info(InfoArgs),
    /// Write one message's stored bytes to standard output.
    Show(ShowArgs),
}

fn main() -> ExitCode {
    let styled = Environment::from_process().styled();
    let choice = if styled {
        ColorChoice::Always
    } else {
        ColorChoice::Never
    };
    let cli = match parse(choice) {
        Ok(cli) => cli,
        Err(error) => return usage_error(&error),
    };
    let feedback = match (cli.quiet || cli.json, styled) {
        (true, _) => Feedback::Silent,
        (false, true) => Feedback::Live,
        (false, false) => Feedback::Summary,
    };
    let report = if cli.json {
        Report::Events
    } else {
        Report::Text
    };
    let outcome = match &cli.command {
        Command::Export(args) => export::run(args, report, feedback),
        Command::Info(args) => info::run(args, report, feedback),
        Command::Show(args) => show::run(args, report, feedback),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => describe(&failure, report),
    }
}

/// Parses the command line with clap's colours fixed to `choice`, so help and usage errors carry
/// escape codes exactly when the progress bar is drawn.
fn parse(choice: ColorChoice) -> Result<Cli, clap::Error> {
    let mut matches = Cli::command().color(choice).try_get_matches()?;
    Cli::from_arg_matches_mut(&mut matches)
}

/// Prints a clap message and returns its exit code; with `--json` among the arguments a usage
/// error is also written as an `error` event, even when the message could not be printed.
fn usage_error(error: &clap::Error) -> ExitCode {
    let json = env::args_os().any(|argument| argument == "--json");
    // A clap message that cannot be written (a closed stdout or stderr) has nowhere left to be
    // reported, so it exits 1, "any other failure", rather than the code it carried.
    let code = if error.print().is_err() {
        1
    } else if error.use_stderr() {
        exit::USAGE
    } else {
        0
    };
    if json && error.use_stderr() && events::error(code, &error.to_string()).is_err() {
        return ExitCode::from(74);
    }
    ExitCode::from(code)
}

/// Prints the failure as one line on stderr and returns its exit code. With events, the same
/// line is also written as the last `error` event, and an event that cannot be written exits 74.
/// A line that cannot be written to stderr has nowhere to go, so it exits 1 like an unwritable
/// clap message, after the event.
fn describe(failure: &Failure, report: Report) -> ExitCode {
    let line = format!("mboxturbo: {failure}");
    let code = if writeln!(io::stderr(), "{line}").is_err() {
        1
    } else {
        failure.code()
    };
    if report == Report::Events && events::error(code, &line).is_err() {
        return ExitCode::from(74);
    }
    ExitCode::from(code)
}
