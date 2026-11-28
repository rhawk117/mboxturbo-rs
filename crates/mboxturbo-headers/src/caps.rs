//! Upper bounds that keep parsing time and memory proportional to the input.
//!
//! Exceeding any cap is reported as an [`crate::IssueKind::CapExceeded`] naming
//! the [`Cap`], never as a panic or an error; the parser keeps what fits under the bound.

/// Maximum number of bytes of one header value a parser reads; later bytes are ignored and
/// reported as [`Cap::HeaderBytes`].
pub const MAX_HEADER_BYTES: usize = 1 << 20;

/// Maximum nesting depth of parenthesised comments; deeper comments are flattened and
/// reported as [`Cap::CommentDepth`].
pub const MAX_COMMENT_DEPTH: usize = 32;

/// Maximum number of entries (addresses, group members, parameters or references) one
/// header yields; further entries are dropped and reported as [`Cap::Entries`].
pub const MAX_ENTRIES: usize = 10_000;

/// Maximum number of `Received` hops parsed from one message; further hops are dropped and
/// reported as [`Cap::ReceivedHops`].
pub const MAX_RECEIVED_HOPS: usize = 256;

/// Maximum number of RFC 2047 encoded words decoded in one header value; later words are
/// left undecoded and reported as [`Cap::EncodedWords`].
pub const MAX_ENCODED_WORDS: usize = 1_000;

/// Names the cap an [`crate::IssueKind::CapExceeded`] issue refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Cap {
    /// [`MAX_COMMENT_DEPTH`] was exceeded.
    CommentDepth,
    /// [`MAX_ENCODED_WORDS`] was exceeded.
    EncodedWords,
    /// [`MAX_ENTRIES`] was exceeded.
    Entries,
    /// [`MAX_HEADER_BYTES`] was exceeded.
    HeaderBytes,
    /// [`MAX_RECEIVED_HOPS`] was exceeded.
    ReceivedHops,
}
