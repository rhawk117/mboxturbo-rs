//! The failure every subcommand returns, and the helpers that build one.

use std::error::Error as _;
use std::path::PathBuf;
use std::{fmt, io};

use mboxturbo::MboxTurboError;

use crate::dates::DateError;
use crate::exit::{self, Stage};
use crate::select::SelectError;

/// Why an export failed, and so which exit code it gets.
#[derive(Debug)]
pub(crate) enum Failure {
    /// The library failed at this stage.
    Core {
        /// The library error.
        error: Box<MboxTurboError>,
        /// Whether the mailbox was open when it failed.
        stage: Stage,
    },
    /// A termination signal stopped the export; the process exits with the signal's code.
    Interrupted {
        /// The library's cancellation error.
        error: Box<MboxTurboError>,
        /// The exit code of the signal that arrived.
        code: u8,
    },
    /// The command line was well formed but asks for something that cannot be done.
    Usage(String),
}

impl Failure {
    /// The process exit code for this failure.
    pub(crate) fn code(&self) -> u8 {
        match self {
            Self::Core { error, stage } => exit::error_code(*stage, error),
            Self::Interrupted { code, .. } => *code,
            Self::Usage(_) => exit::USAGE,
        }
    }

    /// A library failure anywhere but opening the mailbox.
    pub(crate) const fn other(error: Box<MboxTurboError>) -> Self {
        Self::Core {
            error,
            stage: Stage::Other,
        }
    }
}

impl fmt::Display for Failure {
    #[expect(
        clippy::renamed_function_params,
        reason = "the trait calls it `f`, a one-letter name the min_ident_chars lint bans"
    )]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core { error, .. } => write_chain(formatter, error),
            Self::Interrupted { error, .. } => {
                formatter.write_str("interrupted: ")?;
                write_chain(formatter, error)
            },
            Self::Usage(message) => formatter.write_str(message),
        }
    }
}

impl From<DateError> for Failure {
    fn from(error: DateError) -> Self {
        Self::Usage(error.to_string())
    }
}

impl From<SelectError> for Failure {
    fn from(error: SelectError) -> Self {
        Self::Usage(error.to_string())
    }
}

/// Writes `error` and each of its causes, separated by `: `.
fn write_chain(formatter: &mut fmt::Formatter<'_>, error: &MboxTurboError) -> fmt::Result {
    write!(formatter, "{error}")?;
    let mut cause = error.source();
    while let Some(source) = cause {
        write!(formatter, ": {source}")?;
        cause = source.source();
    }
    Ok(())
}

/// An event that could not be written to standard output, as an I/O failure.
pub(crate) fn stdout_failure(source: io::Error) -> Failure {
    Failure::other(Box::new(MboxTurboError::Io {
        path: PathBuf::from("standard output"),
        source,
    }))
}

/// Signal handlers that could not be installed, as an I/O failure.
pub(crate) fn signal_failure(source: io::Error) -> Failure {
    Failure::other(Box::new(MboxTurboError::Io {
        path: PathBuf::from("signal handlers"),
        source,
    }))
}

/// A line that could not be written to standard error, as an I/O failure.
pub(crate) fn stderr_failure(source: io::Error) -> Failure {
    Failure::other(Box::new(MboxTurboError::Io {
        path: PathBuf::from("standard error"),
        source,
    }))
}
