//! Opening the mailbox a subcommand works on.

use std::io;
use std::path::Path;

use mboxturbo::{IndexPolicy, Mailbox, MailboxBuilder, MboxTurboError};

use crate::exit::Stage;
use crate::failure::Failure;

/// Opens the mailbox, with the index at `index` when one is named.
pub(crate) fn open(path: &Path, index: Option<&Path>) -> Result<Mailbox, Failure> {
    let policy = index.map_or(IndexPolicy::Sidecar, |index_path| {
        IndexPolicy::Path(index_path.to_path_buf())
    });
    MailboxBuilder::new()
        .index(policy)
        .open(path)
        .map_err(|error| {
            let stage = if is_missing(&error, path) {
                Stage::OpeningMailbox
            } else {
                Stage::Other
            };
            Failure::Core {
                error: Box::new(error),
                stage,
            }
        })
}

/// Whether `error` is the mailbox at `mailbox` not existing, as opposed to any other missing path
/// such as the index directory.
fn is_missing(error: &MboxTurboError, mailbox: &Path) -> bool {
    matches!(
        error,
        MboxTurboError::Io { path, source }
            if path == mailbox && source.kind() == io::ErrorKind::NotFound
    )
}
