//! The `mboxturbo` command-line exporter for large mbox files.
//!
//! Every outcome becomes one process exit code, chosen by `exit::outcome_code`:
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0 | success, including `--help` and `--version` |
//! | 1 | any other failure |
//! | 64 | usage error: bad arguments, or a message position past the last message |
//! | 65 | corrupt or stale index |
//! | 66 | the mailbox does not exist |
//! | 73 | the export target exists and `--overwrite` was not given |
//! | 74 | any other I/O error |
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

mod exit;

use std::process::ExitCode;

use clap::Parser;

/// Exit code for a command line that clap rejects.
const USAGE: u8 = 64;

/// Exports large mbox files to analysis-friendly formats.
#[derive(Debug, Parser)]
#[command(name = "mboxturbo", version, about)]
struct Cli;

fn main() -> ExitCode {
    let Cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let code = if error.use_stderr() { USAGE } else { 0 };
            return match error.print() {
                Ok(()) => ExitCode::from(code),
                Err(_) => ExitCode::from(1),
            };
        },
    };
    ExitCode::from(exit::outcome_code(&Ok(())))
}
