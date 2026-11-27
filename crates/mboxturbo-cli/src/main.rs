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
//! | 130 | interrupted (the export was cancelled) |
#![expect(
    clippy::redundant_pub_crate,
    reason = "contradicts rustc's unreachable_pub, which is the lint this workspace keeps"
)]
#![expect(
    clippy::multiple_crate_versions,
    reason = "build-time only: arrow's ahash compiles zerocopy-derive on syn 2 while thiserror 2 \
              uses syn 3"
)]

mod events;
mod exit;
mod export;
mod select;

use std::env;
use std::io::{self, Write as _};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::events::Report;
use crate::export::{ExportArgs, Failure};

/// Exports large mbox files to analysis-friendly formats.
#[derive(Debug, Parser)]
#[command(name = "mboxturbo", version, about)]
struct Cli {
    /// What to do.
    #[command(subcommand)]
    command: Command,
    /// Write a versioned JSON Lines event stream on standard output instead of human text.
    #[arg(long, global = true)]
    json: bool,
}

/// The subcommands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Write the selected messages of a mailbox as parquet, eml, mbox, jsonl, csv or arrow.
    Export(ExportArgs),
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => return usage_error(&error),
    };
    let report = if cli.json {
        Report::Events
    } else {
        Report::Text
    };
    let Command::Export(args) = cli.command;
    match export::run(&args, report) {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => describe(&failure, report),
    }
}

/// Prints a clap message and returns its exit code; with `--json` among the arguments a usage
/// error is also written as an `error` event.
fn usage_error(error: &clap::Error) -> ExitCode {
    let code = if error.use_stderr() { exit::USAGE } else { 0 };
    // A clap message that cannot be written (a closed stdout or stderr) has nowhere left to be
    // reported, so it exits 1, "any other failure", rather than the code it carried.
    if error.print().is_err() {
        return ExitCode::from(1);
    }
    let json = env::args_os().any(|argument| argument == "--json");
    if json && error.use_stderr() && events::error(code, &error.to_string()).is_err() {
        return ExitCode::from(74);
    }
    ExitCode::from(code)
}

/// Prints the failure as one line on stderr and returns its exit code; a line that cannot be
/// written has nowhere to go, so it exits 1 like an unwritable clap message. With events, the
/// same line is also written as the last `error` event, and an event that cannot be written exits
/// 74.
fn describe(failure: &Failure, report: Report) -> ExitCode {
    let line = format!("mboxturbo: {failure}");
    if writeln!(io::stderr(), "{line}").is_err() {
        return ExitCode::from(1);
    }
    if report == Report::Events && events::error(failure.code(), &line).is_err() {
        return ExitCode::from(74);
    }
    ExitCode::from(failure.code())
}
