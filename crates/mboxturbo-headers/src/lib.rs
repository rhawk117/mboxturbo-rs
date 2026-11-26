//! Total parsers for email header values.
//!
//! Every parser in this crate takes the bytes of one header value and returns a [`Parsed`]:
//! the best value that could be recovered plus the [`Issue`]s found on the way. Malformed
//! input is never a panic and never an error; it is an issue with the byte offset where the
//! problem starts. Input that exceeds one of the caps, such as [`MAX_HEADER_BYTES`], is
//! truncated or skipped and reported as [`IssueKind::CapExceeded`].

mod arc;
mod auth_results;
mod caps;
mod date;
mod dkim;
mod encoded_word;
mod issue;
mod tokenize;
mod trust;

pub use arc::{ArcHeader, ArcSet, ChainValidation, parse_arc_sets};
pub use auth_results::{
    AuthMethod, AuthProperty, AuthResult, AuthenticationResults, ResInfo, TrustStatus,
    parse_authentication_results,
};
pub use caps::{
    Cap, MAX_COMMENT_DEPTH, MAX_ENCODED_WORDS, MAX_ENTRIES, MAX_HEADER_BYTES, MAX_RECEIVED_HOPS,
};
pub use date::{Instant, parse_date};
pub use dkim::{DkimSignature, RequiredTag, Tag, TagList, parse_dkim_signature, parse_tag_list};
pub use encoded_word::decode_encoded_words;
pub use issue::{ArcPart, ArcProblem, Issue, IssueKind, Parsed};
pub use tokenize::{Token, TokenKind, tokenize};
pub use trust::{InvalidIpRange, TrustSet};
