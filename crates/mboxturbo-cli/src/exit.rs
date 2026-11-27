//! Maps command outcomes to process exit codes.

use std::io;

use mboxturbo::MboxTurboError;

/// Exit code for success.
const OK: u8 = 0;
/// Exit code for a failure with no more specific code.
const OTHER: u8 = 1;
/// Exit code for a usage error.
const USAGE: u8 = 64;
/// Exit code for a corrupt or stale index.
const CORRUPT: u8 = 65;
/// Exit code for a missing mailbox.
const NOT_FOUND: u8 = 66;
/// Exit code for an export target that exists without `--overwrite`.
const TARGET_EXISTS: u8 = 73;
/// Exit code for any other I/O error.
const IO: u8 = 74;
/// Exit code for an interrupted export.
const INTERRUPTED: u8 = 130;

/// Where a failure arose, which decides whether a `NotFound` means the mailbox is missing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Stage {
    /// Everything after the mailbox is open, such as writing the export.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the export commands that fail after opening are not built yet"
        )
    )]
    AfterOpen,
    /// Opening the mailbox: the only stage whose `NotFound` is a missing mailbox.
    OpeningMailbox,
}

/// Maps the outcome of a command to its process exit code.
///
/// | Outcome | Code |
/// |---------|------|
/// | `Ok` | 0 |
/// | other failure (Arrow, Parquet, unsupported destination, any future variant) | 1 |
/// | `PositionOutOfRange` (usage) | 64 |
/// | `CorruptIndex`, `StaleIndex` | 65 |
/// | `Io` whose source is `NotFound` while opening the mailbox (mailbox missing) | 66 |
/// | `TargetExists` | 73 |
/// | `Io`, any other kind or any `NotFound` after the mailbox is open | 74 |
/// | `Cancelled` | 130 |
///
/// Clap usage errors are mapped to 64 by `main`, not here.
pub(crate) fn outcome_code(stage: Stage, outcome: &Result<(), MboxTurboError>) -> u8 {
    match outcome {
        Ok(()) => OK,
        Err(error) => error_code(stage, error),
    }
}

/// Maps one failure to its exit code; the table is on [`outcome_code`].
#[expect(
    clippy::match_same_arms,
    reason = "the variants that mean `other` are named so a new variant is a conscious choice"
)]
fn error_code(stage: Stage, error: &MboxTurboError) -> u8 {
    match error {
        MboxTurboError::Arrow { .. }
        | MboxTurboError::Parquet { .. }
        | MboxTurboError::UnsupportedDestination { .. } => OTHER,
        MboxTurboError::Cancelled { .. } => INTERRUPTED,
        MboxTurboError::CorruptIndex { .. } | MboxTurboError::StaleIndex { .. } => CORRUPT,
        MboxTurboError::Io { source, .. } => io_code(stage, source),
        MboxTurboError::PositionOutOfRange { .. } => USAGE,
        MboxTurboError::TargetExists { .. } => TARGET_EXISTS,
        // `MboxTurboError` is `#[non_exhaustive]`: a variant added later is "other" until named
        // above.
        _ => OTHER,
    }
}

/// `NotFound` while opening the mailbox means the mailbox is missing; every other I/O failure,
/// including a `NotFound` on an output path, is a plain I/O error.
fn io_code(stage: Stage, source: &io::Error) -> u8 {
    if stage == Stage::OpeningMailbox && source.kind() == io::ErrorKind::NotFound {
        NOT_FOUND
    } else {
        IO
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use mboxturbo::{Corruption, DestinationKind, Mailbox};

    use super::*;

    fn code(error: MboxTurboError) -> u8 {
        outcome_code(Stage::AfterOpen, &Err(error))
    }

    fn opening_code(error: MboxTurboError) -> u8 {
        outcome_code(Stage::OpeningMailbox, &Err(error))
    }

    #[test]
    fn success_exits_zero() {
        assert_eq!(
            outcome_code(Stage::AfterOpen, &Ok(())),
            0,
            "success is exit 0"
        );
    }

    #[test]
    fn opening_a_missing_mailbox_exits_66() {
        let error = Mailbox::open("/nonexistent/mboxturbo-cli-test.mbox")
            .expect_err("the path does not exist");
        assert_eq!(
            opening_code(error),
            66,
            "a NotFound open is a missing mailbox"
        );
    }

    #[test]
    fn not_found_after_the_mailbox_is_open_exits_74() {
        let error = MboxTurboError::Io {
            path: PathBuf::from("out/missing-dir/out.csv"),
            source: io::Error::from(io::ErrorKind::NotFound),
        };
        assert_eq!(
            code(error),
            74,
            "a missing output path is not a missing mailbox"
        );
    }

    #[test]
    fn other_io_errors_exit_74() {
        let source = io::Error::from(io::ErrorKind::PermissionDenied);
        assert_eq!(
            code(MboxTurboError::Io {
                path: PathBuf::from("mail.mbox"),
                source
            }),
            74,
            "non-NotFound I/O is 74"
        );
    }

    #[test]
    fn corrupt_and_stale_indexes_exit_65() {
        let path = PathBuf::from("a.mbxidx");
        let corrupt = MboxTurboError::CorruptIndex {
            path: path.clone(),
            corruption: Corruption::Checksum,
        };
        assert_eq!(code(corrupt), 65, "a corrupt index is 65");
        assert_eq!(
            code(MboxTurboError::StaleIndex { path }),
            65,
            "a stale index is 65"
        );
    }

    #[test]
    fn an_existing_target_exits_73() {
        let error = MboxTurboError::TargetExists {
            path: PathBuf::from("out.csv"),
        };
        assert_eq!(code(error), 73, "target exists is 73");
    }

    #[test]
    fn a_cancelled_export_exits_130() {
        let error = MboxTurboError::Cancelled {
            target: None,
            written: 3,
        };
        assert_eq!(code(error), 130, "interrupted is 130");
    }

    #[test]
    fn a_position_past_the_end_exits_64() {
        let error = MboxTurboError::PositionOutOfRange {
            position: 9,
            len: 3,
        };
        assert_eq!(code(error), 64, "an out-of-range position is a usage error");
    }

    #[test]
    fn an_unsupported_destination_exits_1() {
        let error = MboxTurboError::UnsupportedDestination {
            kind: DestinationKind::Stream,
            target: None,
        };
        assert_eq!(code(error), 1, "an unsupported destination is exit 1");
    }
}
