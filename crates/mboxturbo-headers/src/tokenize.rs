//! The shared header tokenizer: unfolding, comments, quoted strings and lossy decoding in one
//! bounded pass.
//!
//! The scanner is a single loop over the bytes with an explicit depth counter for comment
//! nesting, so hostile input cannot exhaust the stack.

use std::borrow::Cow;

use crate::caps::{Cap, MAX_COMMENT_DEPTH, MAX_HEADER_BYTES};
use crate::issue::{Issue, IssueKind, Parsed};

/// What a [`Token`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TokenKind {
    /// A run of bytes that is not whitespace, a special, a quote or a comment.
    Atom,
    /// A parenthesised comment; its text excludes the outer parentheses and keeps nested ones.
    Comment,
    /// A double-quoted string; its text excludes the quotes and has escapes resolved.
    QuotedString,
    /// One of the delimiters `; = : / @ , < > [ ] . )`, carried as its byte.
    Special(u8),
}

/// One lexical unit of a header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token<'src> {
    /// What the token is.
    kind: TokenKind,
    /// Byte offset in the original value where the token starts, at the opening delimiter
    /// for quoted strings and comments.
    offset: usize,
    /// The decoded text, borrowed when no unescaping, unfolding or lossy decoding was needed.
    text: Cow<'src, str>,
}

impl Token<'_> {
    /// What the token is.
    #[must_use]
    pub const fn kind(&self) -> TokenKind {
        self.kind
    }

    /// Byte offset in the original value where the token starts. For quoted strings and
    /// comments this is the opening delimiter, not the first content byte.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// The token text: lossily decoded, with folds removed and backslash escapes resolved
    /// inside quoted strings and comments. For [`TokenKind::Special`] it is the delimiter itself.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// The two bracketing constructs that hold arbitrary content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Delim {
    /// `( ... )`, which nests.
    Comment,
    /// `" ... "`, which does not.
    Quote,
}

/// How one byte inside a [`Delim`] body is treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    /// A line break byte, dropped because folding is undone.
    Break,
    /// A closing delimiter.
    Close,
    /// A backslash, dropped together with taking the next byte literally.
    Escape,
    /// An opening parenthesis inside a comment.
    Open,
    /// Any other byte, kept as is.
    Plain,
}

impl Delim {
    /// Classifies `byte` as it appears inside this construct.
    const fn classify(self, byte: u8) -> Class {
        match (byte, self) {
            (b'\\', _) => Class::Escape,
            (b'\r' | b'\n', _) => Class::Break,
            (b'"', Self::Quote) | (b')', Self::Comment) => Class::Close,
            (b'(', Self::Comment) => Class::Open,
            _ => Class::Plain,
        }
    }

    /// The issue reported when this construct is still open at the end of the value.
    const fn unterminated(self) -> IssueKind {
        match self {
            Self::Comment => IssueKind::UnterminatedComment,
            Self::Quote => IssueKind::UnterminatedQuote,
        }
    }
}

/// What the body scanner does after one byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    /// Move forward by this many bytes.
    Advance(usize),
    /// The construct closed at the current byte.
    Closed,
}

/// The result of scanning the inside of a quoted string or comment.
#[derive(Debug)]
struct Body {
    /// Whether the closing delimiter was found.
    closed: bool,
    /// Current comment nesting depth; the outermost comment is depth 1.
    depth: usize,
    /// Offset one past the last content byte.
    end: usize,
    /// Offsets of content bytes that are dropped from the text, ascending.
    skips: Vec<usize>,
    /// Offset of the content's first byte.
    start: usize,
    /// Offset of the first parenthesis that exceeded [`MAX_COMMENT_DEPTH`].
    too_deep: Option<usize>,
}

impl Body {
    /// Handles the closing delimiter at `pos`.
    const fn close(&mut self, pos: usize) -> Flow {
        self.depth = self.depth.saturating_sub(1);
        if self.depth > 0 {
            return Flow::Advance(1);
        }
        self.closed = true;
        self.end = pos;
        Flow::Closed
    }

    /// Consumes the byte at `pos` under `delim` and says how far to move.
    fn feed(&mut self, byte: u8, pos: usize, delim: Delim) -> Flow {
        match delim.classify(byte) {
            Class::Close => self.close(pos),
            Class::Open => self.open(pos),
            Class::Escape => self.skip(pos, 2),
            Class::Break => self.skip(pos, 1),
            Class::Plain => Flow::Advance(1),
        }
    }

    /// Starts scanning the body whose content begins at `start`.
    const fn new(start: usize) -> Self {
        Self {
            closed: false,
            depth: 1,
            end: start,
            skips: Vec::new(),
            start,
            too_deep: None,
        }
    }

    /// Handles a nested opening parenthesis at `pos`.
    const fn open(&mut self, pos: usize) -> Flow {
        self.depth = self.depth.saturating_add(1);
        if self.depth > MAX_COMMENT_DEPTH && self.too_deep.is_none() {
            self.too_deep = Some(pos);
        }
        Flow::Advance(1)
    }

    /// Drops the byte at `pos` from the text and advances by `step`.
    fn skip(&mut self, pos: usize, step: usize) -> Flow {
        self.skips.push(pos);
        Flow::Advance(step)
    }
}

/// The scanning state: a position in `bytes` and what has been found so far.
struct Scanner<'src> {
    /// The bounded input.
    bytes: &'src [u8],
    /// Issues found so far.
    issues: Vec<Issue>,
    /// Offset of the next unread byte.
    pos: usize,
    /// Tokens found so far.
    tokens: Vec<Token<'src>>,
}

impl<'src> Scanner<'src> {
    /// Scans one atom starting at the current position.
    fn atom(&mut self) {
        let start = self.pos;
        let rest = self.slice(start, self.bytes.len());
        let len = rest.iter().take_while(|byte| !ends_atom(**byte)).count();
        let end = start.saturating_add(len);
        let text = String::from_utf8_lossy(self.slice(start, end));
        self.pos = end;
        self.push(TokenKind::Atom, start, text);
    }

    /// The decoded text of `body`, borrowed when nothing was dropped.
    fn body_text(&self, body: &Body) -> Cow<'src, str> {
        let content = self.slice(body.start, body.end);
        if body.skips.is_empty() {
            return String::from_utf8_lossy(content);
        }
        let kept: Vec<u8> = content
            .iter()
            .enumerate()
            .filter(|(index, _)| {
                let offset = body.start.saturating_add(*index);
                body.skips.binary_search(&offset).is_err()
            })
            .map(|(_, byte)| *byte)
            .collect();
        Cow::Owned(String::from_utf8_lossy(&kept).into_owned())
    }

    /// Scans a quoted string or comment starting at the current position.
    fn delimited(&mut self, delim: Delim) {
        let open = self.pos;
        let body = self.scan_body(open, delim);
        self.pos = if body.closed {
            body.end.saturating_add(1)
        } else {
            self.bytes.len()
        };
        if !body.closed {
            self.issues.push(Issue::new(delim.unterminated(), open));
        }
        if let Some(deep) = body.too_deep {
            let cap = IssueKind::CapExceeded {
                cap: Cap::CommentDepth,
            };
            self.issues.push(Issue::new(cap, deep));
            return;
        }
        let kind = match delim {
            Delim::Comment => TokenKind::Comment,
            Delim::Quote => TokenKind::QuotedString,
        };
        let text = self.body_text(&body);
        self.push(kind, open, text);
    }

    /// Records a token.
    fn push(&mut self, kind: TokenKind, offset: usize, text: Cow<'src, str>) {
        self.tokens.push(Token { kind, offset, text });
    }

    /// Walks the inside of the construct opened at `open`, up to its close or the end.
    fn scan_body(&self, open: usize, delim: Delim) -> Body {
        let mut body = Body::new(open.saturating_add(1));
        let mut pos = body.start;
        while let Some(&byte) = self.bytes.get(pos) {
            match body.feed(byte, pos, delim) {
                Flow::Closed => return body,
                Flow::Advance(step) => pos = pos.saturating_add(step),
            }
        }
        body.end = self.bytes.len();
        body
    }

    /// The bytes in `start..end`; both bounds are always within the input by construction,
    /// so the empty fallback is unreachable.
    fn slice(&self, start: usize, end: usize) -> &'src [u8] {
        self.bytes.get(start..end).unwrap_or(&[])
    }

    /// Emits a one-byte special token and moves past it.
    fn special(&mut self, byte: u8) {
        let text = String::from_utf8_lossy(self.slice(self.pos, self.pos.saturating_add(1)));
        self.push(TokenKind::Special(byte), self.pos, text);
        self.pos = self.pos.saturating_add(1);
    }

    /// Reads one token or skips one whitespace byte; false once the input is used up.
    fn step(&mut self) -> bool {
        let Some(&byte) = self.bytes.get(self.pos) else {
            return false;
        };
        match byte {
            b'"' => self.delimited(Delim::Quote),
            b'(' => self.delimited(Delim::Comment),
            _ if is_space(byte) => self.pos = self.pos.saturating_add(1),
            _ if is_special(byte) => self.special(byte),
            _ => self.atom(),
        }
        true
    }
}

/// Whether `byte` is whitespace outside quoted strings and comments.
const fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

/// Whether `byte` is a delimiter that forms its own [`TokenKind::Special`] token.
const fn is_special(byte: u8) -> bool {
    matches!(
        byte,
        b';' | b'=' | b':' | b'/' | b'@' | b',' | b'<' | b'>' | b'[' | b']' | b'.' | b')'
    )
}

/// Whether `byte` ends an atom.
const fn ends_atom(byte: u8) -> bool {
    is_space(byte) || is_special(byte) || matches!(byte, b'"' | b'(')
}

/// Truncates `value` to [`MAX_HEADER_BYTES`], reporting the cut.
fn bound(value: &[u8]) -> (&[u8], Vec<Issue>) {
    match value.split_at_checked(MAX_HEADER_BYTES) {
        Some((head, tail)) if !tail.is_empty() => {
            let cap = IssueKind::CapExceeded {
                cap: Cap::HeaderBytes,
            };
            (head, vec![Issue::new(cap, MAX_HEADER_BYTES)])
        },
        _ => (value, Vec::new()),
    }
}

/// One [`IssueKind::InvalidUtf8`] issue for each invalid sequence in `bytes`.
fn invalid_utf8_issues(bytes: &[u8]) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut offset = 0_usize;
    for chunk in bytes.utf8_chunks() {
        offset = offset.saturating_add(chunk.valid().len());
        if !chunk.invalid().is_empty() {
            issues.push(Issue::new(IssueKind::InvalidUtf8, offset));
        }
        offset = offset.saturating_add(chunk.invalid().len());
    }
    issues
}

/// Splits one header value into tokens.
///
/// Folds (a line break followed by whitespace) are undone inside quoted strings and
/// comments and act as plain whitespace elsewhere, so a folded value yields the same
/// tokens as its unfolded form. Each token's offset is into `value` as given. Invalid
/// UTF-8 is decoded as U+FFFD and reported as [`IssueKind::InvalidUtf8`] at each invalid
/// sequence. Input past [`MAX_HEADER_BYTES`] is dropped and reported; a comment nested
/// deeper than [`MAX_COMMENT_DEPTH`] is dropped whole and reported; an unterminated
/// comment or quoted string keeps what was read and is reported at its opening
/// delimiter. Issues are ordered by offset.
#[must_use]
pub fn tokenize(value: &[u8]) -> Parsed<Vec<Token<'_>>> {
    let (bytes, mut issues) = bound(value);
    issues.extend(invalid_utf8_issues(bytes));
    let mut scanner = Scanner {
        bytes,
        issues,
        pos: 0,
        tokens: Vec::new(),
    };
    while scanner.step() {}
    scanner.issues.sort_by_key(Issue::offset);
    Parsed::new(scanner.tokens, scanner.issues)
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::iter::repeat_n;

    use super::{Token, TokenKind, tokenize};
    use crate::caps::{Cap, MAX_COMMENT_DEPTH, MAX_HEADER_BYTES};
    use crate::issue::{Issue, IssueKind};

    fn shape(value: &[u8]) -> Vec<(TokenKind, String)> {
        tokenize(value)
            .value()
            .iter()
            .map(|token| (token.kind(), token.text().to_owned()))
            .collect()
    }

    fn kinds(value: &[u8]) -> Vec<(IssueKind, usize)> {
        tokenize(value)
            .issues()
            .iter()
            .map(|issue| (issue.kind(), issue.offset()))
            .collect()
    }

    fn nested(depth: usize) -> Vec<u8> {
        let mut value = b"a ".to_vec();
        value.extend(repeat_n(b'(', depth));
        value.extend(repeat_n(b')', depth));
        value.extend_from_slice(b" b");
        value
    }

    #[test]
    fn a_folded_value_yields_the_same_tokens_as_its_unfolded_form() {
        let folded = b"text/plain;\r\n charset=\"us-\r\n ascii\" (a\r\n  (b\\)))\r\n boundary=x";
        let unfolded = b"text/plain; charset=\"us- ascii\" (a  (b\\))) boundary=x";
        assert_eq!(
            shape(folded),
            shape(unfolded),
            "folding must not change kinds or texts"
        );
        assert!(
            tokenize(folded).issues().is_empty(),
            "a well-formed folded value has no issues"
        );
    }

    #[test]
    fn each_token_carries_its_start_offset_in_the_original_value() {
        let parsed = tokenize(b"a=\"b c\" (d)\r\n e");
        let offsets: Vec<_> = parsed.value().iter().map(Token::offset).collect();
        assert_eq!(
            offsets,
            vec![0, 1, 2, 8, 14],
            "quoted and comment tokens start at their opening delimiter"
        );
    }

    #[test]
    fn escapes_in_quoted_strings_and_comments_are_resolved() {
        assert_eq!(
            shape(b"\"a\\\"b\\\\\" (c\\)d)"),
            vec![
                (TokenKind::QuotedString, "a\"b\\".to_owned()),
                (TokenKind::Comment, "c)d".to_owned()),
            ],
            "backslash takes the next byte literally"
        );
    }

    #[test]
    fn clean_ascii_text_is_borrowed_and_unescaped_text_is_owned() {
        let parsed = tokenize(b"abc \"def\" \"g\\h\"");
        let borrowed: Vec<_> = parsed
            .value()
            .iter()
            .map(|token| matches!(token.text, Cow::Borrowed(_)))
            .collect();
        assert_eq!(
            borrowed,
            vec![true, true, false],
            "only the token that needed unescaping allocates"
        );
    }

    #[test]
    fn invalid_utf8_is_decoded_lossily_and_reported_at_its_offset() {
        let parsed = tokenize(b"ab \xff\xfecd");
        assert_eq!(
            shape(b"ab \xff\xfecd")[1],
            (TokenKind::Atom, "\u{fffd}\u{fffd}cd".to_owned()),
            "each invalid byte becomes U+FFFD"
        );
        assert_eq!(
            parsed.issues(),
            [
                Issue::new(IssueKind::InvalidUtf8, 3),
                Issue::new(IssueKind::InvalidUtf8, 4)
            ],
            "each invalid sequence is reported where it starts"
        );
    }

    #[test]
    fn comments_nested_past_the_cap_are_skipped_and_reported() {
        let cap = IssueKind::CapExceeded {
            cap: Cap::CommentDepth,
        };
        assert_eq!(
            shape(&nested(MAX_COMMENT_DEPTH)).len(),
            3,
            "a comment exactly at the cap is kept"
        );
        assert_eq!(
            shape(&nested(MAX_COMMENT_DEPTH + 1)),
            vec![
                (TokenKind::Atom, "a".to_owned()),
                (TokenKind::Atom, "b".to_owned())
            ],
            "the too-deep comment is dropped whole"
        );
        assert_eq!(
            kinds(&nested(MAX_COMMENT_DEPTH + 1)),
            vec![(cap, 2 + MAX_COMMENT_DEPTH)],
            "reported at the first parenthesis over the cap"
        );
    }

    #[test]
    fn a_million_open_parentheses_do_not_overflow_the_stack() {
        let value = vec![b'('; MAX_HEADER_BYTES];
        assert_eq!(
            kinds(&value)
                .iter()
                .filter(|(kind, _)| *kind == IssueKind::UnterminatedComment)
                .count(),
            1,
            "deep nesting is a loop, so it ends in one unterminated report"
        );
    }

    #[test]
    fn unterminated_comments_and_quotes_are_reported_at_their_opening() {
        assert_eq!(
            kinds(b"a (b c"),
            vec![(IssueKind::UnterminatedComment, 2)],
            "unterminated comment"
        );
        assert_eq!(
            shape(b"a \"b c"),
            vec![
                (TokenKind::Atom, "a".to_owned()),
                (TokenKind::QuotedString, "b c".to_owned())
            ],
            "an unterminated quote keeps what was read"
        );
        assert_eq!(
            kinds(b"a \"b c"),
            vec![(IssueKind::UnterminatedQuote, 2)],
            "unterminated quote"
        );
    }

    #[test]
    fn input_past_the_header_cap_is_truncated_and_reported() {
        let mut value = vec![b'a'; MAX_HEADER_BYTES];
        value.extend_from_slice(b" tail");
        let parsed = tokenize(&value);
        assert_eq!(parsed.value().len(), 1, "the tail past the cap is not read");
        assert_eq!(
            parsed.issues(),
            [Issue::new(
                IssueKind::CapExceeded {
                    cap: Cap::HeaderBytes
                },
                MAX_HEADER_BYTES
            )],
            "the cut is reported at the cap"
        );
    }

    #[test]
    fn specials_are_their_own_tokens() {
        assert_eq!(
            shape(b"a@b.c;d=e/f"),
            ["a", "@", "b", ".", "c", ";", "d", "=", "e", "/", "f"]
                .iter()
                .map(|text| (
                    match *text {
                        "@" | "." | ";" | "=" | "/" => TokenKind::Special(text.as_bytes()[0]),
                        _ => TokenKind::Atom,
                    },
                    (*text).to_owned()
                ))
                .collect::<Vec<_>>(),
            "delimiters split atoms"
        );
    }

    fn offsets_stay_inside(value: &[u8]) -> bool {
        let parsed = tokenize(value);
        parsed
            .value()
            .iter()
            .all(|token| token.offset() < value.len())
            && parsed
                .issues()
                .iter()
                .all(|issue| issue.offset() <= value.len())
    }

    #[test]
    fn every_single_byte_and_adjacent_pair_tokenizes_with_in_range_offsets() {
        for first in 0..=u8::MAX {
            assert!(offsets_stay_inside(&[first]), "single byte {first:#04x}");
            for second in [b'(', b')', b'"', b'\\', b'\r', b'\n', 0xFF, b'a'] {
                assert!(
                    offsets_stay_inside(&[first, second]),
                    "pair {first:#04x} {second:#04x}"
                );
                assert!(
                    offsets_stay_inside(&[b'(', first, second]),
                    "comment {first:#04x} {second:#04x}"
                );
                assert!(
                    offsets_stay_inside(&[b'"', first, second]),
                    "quote {first:#04x} {second:#04x}"
                );
            }
        }
    }
}
