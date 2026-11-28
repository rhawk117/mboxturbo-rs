//! Offset-indexed random access, parallel indexing and zero-copy parsing for large mbox files.
//!
//! [`Mailbox`] maps an mbox file read-only, finds every message boundary with a SIMD scan
//! split across threads, and hands out raw slices or lazily parsed [`Message`]s that borrow
//! straight from the mapping. An [`Index`] can be saved and reloaded; a [`Fingerprint`] ties
//! it to the exact mailbox it was built from.
//!
//! The mailbox file must not be modified or truncated while a [`Mailbox`] or any [`Message`]
//! taken from it is alive: the bytes are memory-mapped, not copied.
#![expect(
    clippy::redundant_pub_crate,
    reason = "contradicts rustc's unreachable_pub, which is the lint this workspace keeps"
)]
#![expect(
    clippy::multiple_crate_versions,
    reason = "build-time only: arrow's ahash compiles zerocopy-derive on syn 2 while thiserror 2 \
              uses syn 3"
)]

mod builder;
mod columns;
mod csv_sink;
mod eml_sink;
mod encode;
mod error;
mod export;
mod fields;
mod filter;
mod fingerprint;
mod hint;
mod index;
mod ipc_sink;
mod jsonl_sink;
mod mailbox;
mod mapping;
mod mbox_sink;
mod message;
mod parquet;
mod pipeline;
mod predicates;
mod scan;
mod selection;
mod staging;
mod stream;
mod structured;
mod verdict;
mod width;

pub use builder::{BoundaryCheck, IndexOrigin, IndexPolicy, IndexSource, MailboxBuilder};
pub use columns::Column;
pub use csv_sink::{CsvExporter, FormulaEscaping};
pub use eml_sink::EmlExporter;
pub use error::{Corruption, MboxTurboError, PredicateFault};
pub use export::{CancelToken, Export, Exporter, Progress};
pub use filter::{Filter, Narrowed, Narrowing};
pub use fingerprint::Fingerprint;
pub use index::{BlockSize, Index, IndexBytes};
pub use ipc_sink::IpcExporter;
pub use jsonl_sink::JsonlExporter;
pub use mailbox::{DateRange, Mailbox, ParsedBatch};
pub use mbox_sink::MboxExporter;
pub use mboxturbo_headers::{TrustSet, civil_from_days, days_from_civil, rfc3339, rfc3339_micros};
pub use message::{Address, Attachment, Message, Timestamp};
pub use parquet::ParquetExporter;
pub use pipeline::{BatchReader, Compression, Pipeline};
pub use predicates::{Predicate, VerdictMethod};
pub use selection::Selection;
pub use staging::{Destination, DestinationKind, ExportSummary, Output, Overwrite, Staged};
