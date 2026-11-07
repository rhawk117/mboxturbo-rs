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
    reason = "build-time only: mail-parser 0.11, pinned for Rust 1.97, compiles hashify on syn 2 \
              while thiserror 2 uses syn 3; mail-parser 1.x on Rust 1.98 removes the split"
)]

mod error;
mod fingerprint;
mod hint;
mod index;
mod mailbox;
mod message;
mod scan;
mod width;

pub use error::{Corruption, Error};
pub use fingerprint::Fingerprint;
pub use index::Index;
pub use mailbox::Mailbox;
pub use message::{Address, Attachment, Message, Timestamp};
