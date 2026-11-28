//! Python bindings for `mboxturbo`: converts types, maps errors, and releases the interpreter
//! while Rust indexes, loads or parses.
#![expect(
    clippy::redundant_pub_crate,
    reason = "contradicts rustc's unreachable_pub, which is the lint this workspace keeps"
)]

mod errors;
mod export;
mod exporter;
mod mailbox;
mod message;
mod predicates;

use pyo3::prelude::*;

/// Offset-indexed random access, parallel indexing and Rust-parsed messages for mbox files.
#[pymodule]
mod _core {
    #[pymodule_export]
    use super::errors::{Cancelled, CorruptIndexError, MboxTurboError, StaleIndexError};
    #[pymodule_export]
    use super::export::{CancelToken, Selection, column_names};
    #[pymodule_export]
    use super::mailbox::Mailbox;
    #[pymodule_export]
    use super::message::{Address, Attachment, Message};
    #[pymodule_export]
    use super::predicates::{HeaderBuilder, Predicate, Trust, VerdictBuilder, header, verdict};
}
