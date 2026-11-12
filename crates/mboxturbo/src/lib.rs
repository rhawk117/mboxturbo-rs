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
mod error;
mod fields;
mod fingerprint;
mod hint;
mod index;
mod mailbox;
mod message;
mod pipeline;
mod scan;
mod width;

pub use builder::{BlockSize, IndexPolicy, IndexSource, MailboxBuilder};
pub use columns::Column;
pub use error::{Corruption, MboxTurboError};
pub use fingerprint::Fingerprint;
pub use index::Index;
pub use mailbox::{Mailbox, ParsedBatch};
pub use message::{Address, Attachment, Message, Timestamp};
pub use pipeline::{BatchReader, Compression, Pipeline};
