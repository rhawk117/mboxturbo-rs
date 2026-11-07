//! Python bindings for `mboxturbo`: converts types, maps errors, and releases the interpreter
//! while Rust indexes, loads or parses.
#![expect(
    clippy::redundant_pub_crate,
    reason = "contradicts rustc's unreachable_pub, which is the lint this workspace keeps"
)]

mod errors;
mod mailbox;
mod message;

use pyo3::prelude::*;

/// Offset-indexed random access, parallel indexing and Rust-parsed messages for mbox files.
#[pymodule]
mod _core {
    #[pymodule_export]
    use super::errors::{CorruptIndexError, MboxTurboError, StaleIndexError};
    #[pymodule_export]
    use super::mailbox::Mailbox;
    #[pymodule_export]
    use super::message::{Address, Attachment, Message};
}
