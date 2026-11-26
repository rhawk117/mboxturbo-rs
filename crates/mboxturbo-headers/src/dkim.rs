//! Parser for DKIM tag lists (RFC 6376 section 3.2), shared by `DKIM-Signature` and the ARC
//! headers that reuse the same grammar.
//!
//! A tag list is `name=value` pairs separated by `;`. There are no comments, so the bytes are
//! scanned for `;` and `=` directly instead of going through the tokenizer.

use std::borrow::Cow;
use std::collections::HashSet;
use std::str::from_utf8;

use crate::caps::{Cap, MAX_ENTRIES};
use crate::issue::{Issue, IssueKind, Parsed};

/// Tags every `DKIM-Signature` must carry (RFC 6376 section 3.5).
const REQUIRED_TAGS: [RequiredTag; 7] = [
    RequiredTag::Version,
    RequiredTag::Algorithm,
    RequiredTag::Signature,
    RequiredTag::BodyHash,
    RequiredTag::Domain,
    RequiredTag::Headers,
    RequiredTag::Selector,
];

/// Tags whose value has folding whitespace removed from inside it, not only around it.
const FOLDED_TAGS: [&str; 2] = ["b", "bh"];

/// The two halves of a `name=value` segment, each trimmed, with where each starts.
struct Pair<'src> {
    /// The tag name, not empty.
    name: &'src [u8],
    /// Offset of the name.
    name_at: usize,
    /// The tag value, possibly empty.
    value: &'src [u8],
    /// Offset of the value.
    value_at: usize,
}

/// One `name=value` pair of a tag list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag<'src> {
    /// The tag name with surrounding whitespace removed.
    name: Cow<'src, str>,
    /// Byte offset of the tag name in the header value.
    offset: usize,
    /// The tag value, trimmed; for `b` and `bh` all folding whitespace is removed.
    value: Cow<'src, str>,
}

impl Tag<'_> {
    /// The tag name with surrounding whitespace removed, case preserved.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Byte offset of the tag name in the header value.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// The tag value, trimmed. For `b` and `bh` the folding whitespace inside is removed too.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// The tags of one tag list, in the order they appeared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagList<'src> {
    /// The tags kept, first occurrence of each name only.
    tags: Vec<Tag<'src>>,
}

impl<'src> TagList<'src> {
    /// The tag called `name`, matched case-sensitively as RFC 6376 requires.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Tag<'src>> {
        self.tags.iter().find(|tag| tag.name() == name)
    }

    /// The tags kept, in order of appearance; a repeated name appears once, at its first
    /// occurrence.
    #[must_use]
    pub fn tags(&self) -> &[Tag<'src>] {
        &self.tags
    }
}

/// A tag a `DKIM-Signature` must carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RequiredTag {
    /// `a`, the signing algorithm.
    Algorithm,
    /// `bh`, the body hash.
    BodyHash,
    /// `d`, the signing domain.
    Domain,
    /// `h`, the signed header names.
    Headers,
    /// `s`, the selector.
    Selector,
    /// `b`, the signature.
    Signature,
    /// `v`, the version.
    Version,
}

impl RequiredTag {
    /// The tag name as it appears in a signature, such as `bh`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Algorithm => "a",
            Self::BodyHash => "bh",
            Self::Domain => "d",
            Self::Headers => "h",
            Self::Selector => "s",
            Self::Signature => "b",
            Self::Version => "v",
        }
    }
}

/// Tags and issues gathered while walking the segments of a tag list.
#[derive(Default)]
struct Scan<'src> {
    /// Problems found so far.
    issues: Vec<Issue>,
    /// Raw names already kept, to spot repeats in constant time.
    seen: HashSet<&'src [u8]>,
    /// Tags kept so far.
    tags: Vec<Tag<'src>>,
}

/// A parsed `DKIM-Signature` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimSignature<'src> {
    /// Every tag of the signature.
    list: TagList<'src>,
}

impl<'src> DkimSignature<'src> {
    /// The `a` tag, the signing algorithm such as `rsa-sha256`.
    #[must_use]
    pub fn algorithm(&self) -> Option<&str> {
        self.text("a")
    }

    /// The `bh` tag, the base64 body hash with folding whitespace removed.
    #[must_use]
    pub fn body_hash(&self) -> Option<&str> {
        self.text("bh")
    }

    /// The `d` tag, the signing domain.
    #[must_use]
    pub fn domain(&self) -> Option<&str> {
        self.text("d")
    }

    /// The `s` tag, the selector.
    #[must_use]
    pub fn selector(&self) -> Option<&str> {
        self.text("s")
    }

    /// The `b` tag, the base64 signature with folding whitespace removed.
    #[must_use]
    pub fn signature(&self) -> Option<&str> {
        self.text("b")
    }

    /// The names in the `h` tag, split at `:` and trimmed; empty names are skipped. Yields
    /// nothing when the tag is absent.
    pub fn signed_headers(&self) -> impl Iterator<Item = &str> {
        self.text("h")
            .into_iter()
            .flat_map(|names| names.split(':'))
            .map(|name| name.trim_matches(is_fws_char))
            .filter(|name| !name.is_empty())
    }

    /// Every tag of the signature, in order of appearance.
    #[must_use]
    pub const fn tags(&self) -> &TagList<'src> {
        &self.list
    }

    /// The value of the tag called `name`.
    fn text(&self, name: &str) -> Option<&str> {
        self.list.get(name).map(Tag::value)
    }

    /// The `v` tag, the version, normally `1`.
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.text("v")
    }
}

impl<'src> Scan<'src> {
    /// Keeps `pair` unless its name repeats; false when the tag cap stops the scan.
    fn accept(&mut self, pair: &Pair<'src>) -> bool {
        if self.tags.len() >= MAX_ENTRIES {
            let cap = IssueKind::CapExceeded { cap: Cap::Entries };
            self.issues.push(Issue::new(cap, pair.name_at));
            return false;
        }
        if !self.seen.insert(pair.name) {
            self.issues
                .push(Issue::new(IssueKind::RepeatedTag, pair.name_at));
            return true;
        }
        let name = self.text(pair.name, pair.name_at);
        let mut value = self.text(pair.value, pair.value_at);
        if FOLDED_TAGS.contains(&&*name) {
            value = strip_fws(value);
        }
        self.tags.push(Tag {
            offset: pair.name_at,
            name,
            value,
        });
        true
    }

    /// Records a segment the grammar does not allow.
    fn malformed(&mut self, offset: usize) {
        self.issues
            .push(Issue::new(IssueKind::MalformedEntry, offset));
    }

    /// Reads the segment starting at `start`; false once the tag cap is hit and scanning
    /// should stop.
    fn segment(&mut self, segment: &'src [u8], start: usize) -> bool {
        let (body, at) = trim(segment, start);
        if body.is_empty() {
            self.malformed(start);
            return true;
        }
        let Some(pair) = Pair::split(body, at) else {
            self.malformed(at);
            return true;
        };
        self.accept(&pair)
    }

    /// Decodes `bytes`, which start at `offset`, borrowing when they are valid UTF-8.
    fn text(&mut self, bytes: &'src [u8], offset: usize) -> Cow<'src, str> {
        match from_utf8(bytes) {
            Ok(text) => Cow::Borrowed(text),
            Err(error) => {
                let bad = offset.saturating_add(error.valid_up_to());
                self.issues.push(Issue::new(IssueKind::InvalidUtf8, bad));
                Cow::Owned(String::from_utf8_lossy(bytes).into_owned())
            },
        }
    }
}

impl<'src> Pair<'src> {
    /// Splits `body`, a trimmed segment starting at `at`, at its first `=`; none when there is
    /// no `=` or the name is empty.
    fn split(body: &'src [u8], at: usize) -> Option<Self> {
        let eq = body.iter().position(|byte| *byte == b'=')?;
        let (raw_name, from_eq) = body.split_at_checked(eq)?;
        let (_, raw_value) = from_eq.split_first()?;
        let (name, name_at) = trim(raw_name, at);
        if name.is_empty() {
            return None;
        }
        let value_base = at.saturating_add(eq).saturating_add(1);
        let (value, value_at) = trim(raw_value, value_base);
        Some(Self {
            name,
            name_at,
            value,
            value_at,
        })
    }
}

/// Reads a tag list (RFC 6376 section 3.2) from a header value.
///
/// Tag names are case-sensitive and trimmed, as are values; the folding whitespace inside the
/// values of `b` and `bh` is removed. A trailing `;` is allowed. A segment with no `=` or an
/// empty name, and a `;` with nothing before it, are skipped with an
/// [`IssueKind::MalformedEntry`] at the segment. A repeated name keeps its first value and
/// reports [`IssueKind::RepeatedTag`] at the repeat. Text that is not UTF-8 is decoded lossily
/// with [`IssueKind::InvalidUtf8`]. Tags beyond [`MAX_ENTRIES`] are dropped and reported once as
/// [`IssueKind::CapExceeded`] at the first dropped tag.
#[must_use]
pub fn parse_tag_list(value: &[u8]) -> Parsed<TagList<'_>> {
    let mut scan = Scan::default();
    let mut offset = 0_usize;
    let mut segments = value.split(|byte| *byte == b';').peekable();
    while let Some(segment) = segments.next() {
        let trailing = segments.peek().is_none() && trim(segment, offset).0.is_empty();
        if trailing || !scan.segment(segment, offset) {
            break;
        }
        offset = offset.saturating_add(segment.len()).saturating_add(1);
    }
    Parsed::new(TagList { tags: scan.tags }, scan.issues)
}

/// Reads a `DKIM-Signature` value as a tag list and checks that every required tag is there.
///
/// Everything [`parse_tag_list`] reports applies. Each [`RequiredTag`] that is absent is
/// reported as [`IssueKind::MissingTag`] at the end of the value.
#[must_use]
pub fn parse_dkim_signature(value: &[u8]) -> Parsed<DkimSignature<'_>> {
    let (list, mut issues) = parse_tag_list(value).into_parts();
    for tag in REQUIRED_TAGS {
        if list.get(tag.name()).is_none() {
            issues.push(Issue::new(IssueKind::MissingTag { tag }, value.len()));
        }
    }
    Parsed::new(DkimSignature { list }, issues)
}

/// Whether `ch` is folding whitespace: space, tab, CR or LF.
const fn is_fws_char(ch: char) -> bool {
    matches!(ch, ' ' | '\t' | '\r' | '\n')
}

/// Whether `byte` is folding whitespace: space, tab, CR or LF.
const fn is_fws(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

/// Removes every folding whitespace character, borrowing when there is none.
fn strip_fws(text: Cow<'_, str>) -> Cow<'_, str> {
    if !text.contains(is_fws_char) {
        return text;
    }
    Cow::Owned(text.chars().filter(|ch| !is_fws_char(*ch)).collect())
}

/// `bytes` without folding whitespace at either end, and the offset where it starts given
/// that `bytes` starts at `base`.
const fn trim(bytes: &[u8], base: usize) -> (&[u8], usize) {
    let mut rest = bytes;
    let mut start = base;
    while let [first, tail @ ..] = rest {
        if !is_fws(*first) {
            break;
        }
        rest = tail;
        start = start.saturating_add(1);
    }
    while let [head @ .., last] = rest {
        if !is_fws(*last) {
            break;
        }
        rest = head;
    }
    (rest, start)
}

#[cfg(test)]
mod tests {
    use super::{RequiredTag, parse_dkim_signature, parse_tag_list};
    use crate::caps::{Cap, MAX_ENTRIES};
    use crate::issue::IssueKind;

    const RFC_6376_SECTION_3_5: &str = concat!(
        "v=1; a=rsa-sha256; d=example.net; s=brisbane;\r\n",
        " c=simple; q=dns/txt; i=@eng.example.net;\r\n",
        " t=1117574938; x=1118006938;\r\n",
        " h=from:to:subject:date;\r\n",
        " z=From:foo@eng.example.net|To:joe@example.com|\r\n",
        " Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700;\r\n",
        " bh=MTIzNDU2Nzg5MDEy\r\n MzQ1Njc4OTAxMjM0NTY3ODkwMTI=;\r\n",
        " b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZ\r\n",
        "          VoG4ZHRNiYzR"
    );

    const FOLDS: usize = 149_796;

    fn kinds(input: &[u8]) -> Vec<(IssueKind, usize)> {
        parse_tag_list(input)
            .issues()
            .iter()
            .map(|issue| (issue.kind(), issue.offset()))
            .collect()
    }

    fn names(input: &[u8]) -> Vec<String> {
        parse_tag_list(input)
            .value()
            .tags()
            .iter()
            .map(|tag| tag.name().to_owned())
            .collect()
    }

    #[test]
    fn rfc_6376_section_3_5_recovers_every_tag_in_order_without_issues() {
        let parsed = parse_dkim_signature(RFC_6376_SECTION_3_5.as_bytes());
        let signature = parsed.value();
        assert_eq!(
            signature
                .tags()
                .tags()
                .iter()
                .map(super::Tag::name)
                .collect::<Vec<_>>(),
            [
                "v", "a", "d", "s", "c", "q", "i", "t", "x", "h", "z", "bh", "b"
            ],
            "tags keep their order of appearance"
        );
        assert_eq!(signature.version(), Some("1"), "version");
        assert_eq!(signature.algorithm(), Some("rsa-sha256"), "algorithm");
        assert_eq!(signature.domain(), Some("example.net"), "domain");
        assert_eq!(signature.selector(), Some("brisbane"), "selector");
        assert!(parsed.issues().is_empty(), "the RFC example is well formed");
    }

    #[test]
    fn folding_whitespace_is_removed_inside_b_and_bh_only() {
        let parsed = parse_dkim_signature(RFC_6376_SECTION_3_5.as_bytes());
        let signature = parsed.value();
        assert_eq!(
            signature.body_hash(),
            Some("MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="),
            "bh is joined across the fold"
        );
        assert_eq!(
            signature.signature(),
            Some("dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR"),
            "b is joined across the fold"
        );
        let extra = signature
            .tags()
            .get("z")
            .expect("the RFC example has a z tag");
        assert!(
            extra.value().contains("|\r\n Subject"),
            "other tags keep inner folds"
        );
    }

    #[test]
    fn signed_headers_are_split_trimmed_and_skip_empty_names() {
        let parsed = parse_dkim_signature(b"h= from : to ::\r\n subject ;");
        let headers: Vec<_> = parsed.value().signed_headers().collect();
        assert_eq!(headers, ["from", "to", "subject"], "h is a colon list");
    }

    #[test]
    fn a_repeated_tag_keeps_its_first_value_and_reports_the_repeat() {
        let parsed = parse_tag_list(b"v=1; d=a; d=b");
        assert_eq!(
            parsed.value().get("d").map(super::Tag::value),
            Some("a"),
            "first d wins"
        );
        assert_eq!(parsed.value().tags().len(), 2, "the repeat is not kept");
        assert_eq!(
            kinds(b"v=1; d=a; d=b"),
            [(IssueKind::RepeatedTag, 10)],
            "at the repeat"
        );
    }

    #[test]
    fn each_missing_required_tag_is_reported_at_the_end_of_the_value() {
        let parsed = parse_dkim_signature(b"v=1");
        let found: Vec<_> = parsed
            .issues()
            .iter()
            .map(|issue| (issue.kind(), issue.offset()))
            .collect();
        let expected: Vec<_> = [
            RequiredTag::Algorithm,
            RequiredTag::Signature,
            RequiredTag::BodyHash,
            RequiredTag::Domain,
            RequiredTag::Headers,
            RequiredTag::Selector,
        ]
        .into_iter()
        .map(|tag| (IssueKind::MissingTag { tag }, 3))
        .collect();
        assert_eq!(found, expected, "everything but v is missing");
    }

    #[test]
    fn malformed_segments_are_skipped_with_an_issue_at_their_offset() {
        let input = b"a=1; junk; =x; b=2;; c=3";
        assert_eq!(names(input), ["a", "b", "c"], "good tags survive");
        assert_eq!(
            kinds(input),
            [
                (IssueKind::MalformedEntry, 5),
                (IssueKind::MalformedEntry, 11),
                (IssueKind::MalformedEntry, 19),
            ],
            "no =, empty name, stray ;"
        );
    }

    #[test]
    fn a_trailing_semicolon_with_whitespace_is_not_an_issue() {
        assert!(kinds(b"v=1;\r\n ").is_empty(), "RFC 6376 allows a final ;");
    }

    #[test]
    fn empty_and_garbage_input_never_panics_and_reports_offsets() {
        assert!(kinds(b"").is_empty(), "empty input has no issues");
        assert!(names(b"").is_empty(), "empty input has no tags");
        assert_eq!(
            kinds(b"\xff\xfe;;="),
            [
                (IssueKind::MalformedEntry, 0),
                (IssueKind::MalformedEntry, 3),
                (IssueKind::MalformedEntry, 4),
            ],
            "garbage is skipped segment by segment"
        );
    }

    #[test]
    fn invalid_utf8_in_a_value_is_replaced_and_reported_at_the_byte() {
        let parsed = parse_tag_list(b"d=ex\xffample");
        assert_eq!(
            parsed.value().get("d").map(super::Tag::value),
            Some("ex\u{fffd}ample")
        );
        assert_eq!(
            kinds(b"d=ex\xffample"),
            [(IssueKind::InvalidUtf8, 4)],
            "at the byte"
        );
    }

    #[test]
    fn tags_beyond_the_cap_are_dropped_and_reported_once() {
        let input = (0..MAX_ENTRIES + 5)
            .map(|index| format!("t{index}=1;"))
            .collect::<Vec<_>>()
            .concat();
        let parsed = parse_tag_list(input.as_bytes());
        let first_dropped = input
            .find(&format!("t{MAX_ENTRIES}="))
            .expect("the input holds the first dropped tag");
        assert_eq!(
            parsed.value().tags().len(),
            MAX_ENTRIES,
            "tags stop at the cap"
        );
        assert_eq!(
            kinds(input.as_bytes()),
            [(IssueKind::CapExceeded { cap: Cap::Entries }, first_dropped)],
            "one issue at the first dropped tag"
        );
    }

    #[test]
    fn a_one_mebibyte_signature_is_read_whole() {
        let input = format!("b={}", "QUJD\r\n ".repeat(FOLDS));
        let parsed = parse_dkim_signature(input.as_bytes());
        assert_eq!(
            parsed.value().signature().map(str::len),
            Some(4 * FOLDS),
            "all of b is kept with its folds removed"
        );
    }
}
