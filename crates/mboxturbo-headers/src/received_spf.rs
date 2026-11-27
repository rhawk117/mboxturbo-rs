//! Parser for `Received-SPF` header values (RFC 7208 section 9.1).
//!
//! The value is a result word, an optional parenthesised comment and a list of `key=value`
//! pairs separated by `;` (or only by whitespace, as some receivers write them). Tokens that
//! touch with no whitespace or comment between them form one word, which is how
//! `envelope-from=user@example.com` and `client-ip=2001:db8::1` are put back together from the
//! tokenizer's atoms and delimiters.

use std::borrow::Cow;
use std::net::IpAddr;
use std::str::from_utf8;

use crate::caps::{Cap, MAX_ENTRIES};
use crate::issue::{Issue, IssueKind, Parsed};
use crate::tokenize::{Token, TokenKind, tokenize};

/// Results with a dedicated variant, matched ASCII case-insensitively.
static RESULTS: [(&str, SpfResult<'static>); 7] = [
    ("fail", SpfResult::Fail),
    ("neutral", SpfResult::Neutral),
    ("none", SpfResult::None),
    ("pass", SpfResult::Pass),
    ("permerror", SpfResult::PermError),
    ("softfail", SpfResult::SoftFail),
    ("temperror", SpfResult::TempError),
];

/// The verdict a receiver recorded for the SPF check.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpfResult<'src> {
    /// `fail`, the host is not authorized.
    Fail,
    /// `neutral`, the domain makes no assertion about the host.
    Neutral,
    /// `none`, no SPF record was found.
    None,
    /// A result with no variant of its own, kept as written.
    Other(Cow<'src, str>),
    /// `pass`, the host is authorized.
    Pass,
    /// `permerror`, a permanent evaluation error.
    PermError,
    /// `softfail`, the host is probably not authorized.
    SoftFail,
    /// `temperror`, a temporary evaluation error.
    TempError,
}

impl<'src> SpfResult<'src> {
    /// Maps a result word to its variant, keeping an unknown word verbatim.
    fn from_name(name: Cow<'src, str>) -> Self {
        RESULTS
            .iter()
            .find(|(known, _)| known.eq_ignore_ascii_case(&name))
            .map_or(Self::Other(name), |(_, result)| result.clone())
    }
}

/// One `key=value` pair after the result, such as `client-ip=192.0.2.1`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SpfPair<'src> {
    /// The key as written; look pairs up with [`ReceivedSpf::get`] to ignore case.
    pub key: Cow<'src, str>,
    /// Byte offset of the key in the header value.
    pub offset: usize,
    /// The value, with quotes removed.
    pub value: Cow<'src, str>,
}

/// A parsed `Received-SPF` header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedSpf<'src> {
    /// The value of the first `client-ip` pair when it is a valid address.
    client_ip: Option<IpAddr>,
    /// The text of the first parenthesised comment, if any.
    comment: Option<Cow<'src, str>>,
    /// The pairs in header order.
    pairs: Vec<SpfPair<'src>>,
    /// The verdict word.
    result: SpfResult<'src>,
}

impl<'src> ReceivedSpf<'src> {
    /// The value of the first `client-ip` pair when it is a valid address. An invalid one
    /// stays readable as text through [`Self::get`].
    #[must_use]
    pub const fn client_ip(&self) -> Option<IpAddr> {
        self.client_ip
    }

    /// The text of the first parenthesised comment, which usually explains the verdict.
    #[must_use]
    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    /// The first pair named `key`, ignoring ASCII case.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&SpfPair<'src>> {
        self.pairs
            .iter()
            .find(|pair| pair.key.eq_ignore_ascii_case(key))
    }

    /// The pairs in header order, repeated keys included.
    #[must_use]
    pub fn pairs(&self) -> &[SpfPair<'src>] {
        &self.pairs
    }

    /// The verdict word at the start of the value.
    #[must_use]
    pub fn result(&self) -> SpfResult<'src> {
        self.result.clone()
    }
}

/// One non-comment token with the facts the word grouping needs.
struct Item<'tok> {
    /// Whether whitespace or a comment separates this token from the one before it.
    gap: bool,
    /// What the token is.
    kind: TokenKind,
    /// Byte offset of the token in the header value.
    offset: usize,
    /// The token's decoded text.
    text: &'tok str,
}

/// A pair and the items after it, or the byte offset of the problem and the items after the
/// segment that holds it.
type Taken<'src, 'run, 'tok> =
    Result<(SpfPair<'src>, &'run [Item<'tok>]), (usize, &'run [Item<'tok>])>;

/// Reads `value` as a `Received-SPF` body.
///
/// The first word is the result and the first comment is kept as text. Every `key=value`
/// pair after it is kept in order with quotes removed; keys are kept as written. Anything the
/// grammar does not allow, such as a missing result, a key with no `=` or a pair with no
/// value, is reported as [`IssueKind::MalformedEntry`] at its byte offset, the rest of that
/// `;` segment is skipped and the pairs read before and after it are kept. A `client-ip` that
/// is not an IP address is reported the same way at its key and left out of
/// [`ReceivedSpf::client_ip`]. More than [`MAX_ENTRIES`] pairs are dropped and reported once as
/// [`IssueKind::CapExceeded`]. Tokenizer issues are included. Work is linear in the length of
/// `value`.
#[must_use]
pub fn parse_received_spf(value: &[u8]) -> Parsed<ReceivedSpf<'_>> {
    let (tokens, mut issues) = tokenize(value).into_parts();
    let comment = first_comment(value, &tokens);
    let items = items(value, &tokens);
    let head_len = word_len(&items, |item| !is_equals(item) && !is_semicolon(item));
    let (head, rest) = items.split_at(head_len);
    if head.is_empty() {
        issues.push(malformed(
            rest.first().map_or(value.len(), |item| item.offset),
        ));
    }
    let result = SpfResult::from_name(join(value, head));
    let pairs = parse_pairs(value, rest, &mut issues);
    let client_ip = client_ip(&pairs, &mut issues);
    issues.sort_by_key(Issue::offset);
    let parsed = ReceivedSpf {
        client_ip,
        comment,
        pairs,
        result,
    };
    Parsed::new(parsed, issues)
}

/// The text of the first comment in `tokens`, borrowed from `value` when it needs no unfolding.
fn first_comment<'src>(value: &'src [u8], tokens: &[Token<'_>]) -> Option<Cow<'src, str>> {
    let token = tokens
        .iter()
        .find(|token| token.kind() == TokenKind::Comment)?;
    let text = borrowed_comment(value, token)
        .map_or_else(|| Cow::Owned(String::from(token.text())), Cow::Borrowed);
    Some(text)
}

/// The bytes of `value` inside `token`'s parentheses, if they are exactly the token's text.
#[expect(
    clippy::disallowed_methods,
    reason = "invalid UTF-8 only means the text is not borrowable, so the caller builds it owned"
)]
fn borrowed_comment<'src>(value: &'src [u8], token: &Token<'_>) -> Option<&'src str> {
    let start = token.offset().checked_add(1)?;
    let end = start.checked_add(token.text().len())?;
    let inside = value.get(start..end)?;
    if inside != token.text().as_bytes() {
        return None;
    }
    from_utf8(inside).ok()
}

/// Drops comments from `tokens` and marks which tokens are set apart from their predecessor.
fn items<'tok>(value: &[u8], tokens: &'tok [Token<'_>]) -> Vec<Item<'tok>> {
    let mut items = Vec::with_capacity(tokens.len());
    let mut after_comment = false;
    for token in tokens {
        if token.kind() == TokenKind::Comment {
            after_comment = true;
            continue;
        }
        items.push(Item {
            gap: after_comment || preceded_by_space(value, token.offset()),
            kind: token.kind(),
            offset: token.offset(),
            text: token.text(),
        });
        after_comment = false;
    }
    items
}

/// Whether the byte before `offset` is ASCII whitespace, which includes a fold's line break.
fn preceded_by_space(value: &[u8], offset: usize) -> bool {
    offset
        .checked_sub(1)
        .and_then(|before| value.get(before))
        .is_some_and(u8::is_ascii_whitespace)
}

/// Reads each pair of `items`; a segment that holds no pair is skipped after one issue.
fn parse_pairs<'src>(
    value: &'src [u8],
    items: &[Item<'_>],
    issues: &mut Vec<Issue>,
) -> Vec<SpfPair<'src>> {
    let mut pairs = Vec::new();
    let mut rest = skip_semicolons(items);
    while let Some(first) = rest.first() {
        if pairs.len() >= MAX_ENTRIES {
            let cap = Issue::new(IssueKind::CapExceeded { cap: Cap::Entries }, first.offset);
            issues.push(cap);
            break;
        }
        rest = match take_pair(value, rest) {
            Ok((pair, next)) => {
                pairs.push(pair);
                next
            },
            Err((offset, next)) => {
                issues.push(malformed(offset));
                next
            },
        };
        rest = skip_semicolons(rest);
    }
    pairs
}

/// Splits one `key=value` pair off the front of `items`; the value is the touching run after
/// the `=`, so a space ends it.
fn take_pair<'src, 'run, 'tok>(
    value: &'src [u8],
    items: &'run [Item<'tok>],
) -> Taken<'src, 'run, 'tok> {
    let (key, rest) = items.split_at(word_len(items, |item| {
        !is_equals(item) && !is_semicolon(item)
    }));
    let Some((equals, after)) = rest.split_first().filter(|(item, _)| is_equals(item)) else {
        return Err((
            items.first().map_or(0, |item| item.offset),
            skip_segment(items),
        ));
    };
    let (text, next) = after.split_at(word_len(after, |item| !is_semicolon(item)));
    if key.is_empty() || text.first().is_none_or(|item| item.gap) {
        return Err((equals.offset, skip_segment(items)));
    }
    let pair = SpfPair {
        key: join(value, key),
        offset: key.first().map_or(equals.offset, |item| item.offset),
        value: join(value, text),
    };
    Ok((pair, next))
}

/// The first `client-ip` pair's address; one that does not parse is reported at its key.
fn client_ip(pairs: &[SpfPair<'_>], issues: &mut Vec<Issue>) -> Option<IpAddr> {
    let pair = pairs
        .iter()
        .find(|pair| pair.key.eq_ignore_ascii_case("client-ip"))?;
    if let Ok(address) = pair.value.parse::<IpAddr>() {
        return Some(address);
    }
    issues.push(malformed(pair.offset));
    None
}

/// Counts the leading items of one word: the first item, then each item that touches its
/// predecessor and passes `keep`. The first item is taken only if it passes `keep`.
fn word_len(items: &[Item<'_>], keep: impl Fn(&Item<'_>) -> bool) -> usize {
    items
        .iter()
        .enumerate()
        .take_while(|(at, item)| keep(item) && (*at == 0 || !item.gap))
        .count()
}

/// The items after the first `;` of `items`, or none when there is no `;`.
fn skip_segment<'run, 'tok>(items: &'run [Item<'tok>]) -> &'run [Item<'tok>] {
    let end = items
        .iter()
        .position(is_semicolon)
        .map_or(items.len(), |at| at.saturating_add(1));
    items.split_at_checked(end).map_or(&[], |(_, tail)| tail)
}

/// `items` without its leading `;` delimiters.
fn skip_semicolons<'run, 'tok>(items: &'run [Item<'tok>]) -> &'run [Item<'tok>] {
    let count = items.iter().take_while(|item| is_semicolon(item)).count();
    items.split_at_checked(count).map_or(&[], |(_, tail)| tail)
}

/// Joins the text of `items`, borrowing from `value` when they are unquoted and contiguous.
fn join<'src>(value: &'src [u8], items: &[Item<'_>]) -> Cow<'src, str> {
    verbatim(value, items).map_or_else(
        || Cow::Owned(items.iter().map(|item| item.text).collect()),
        Cow::Borrowed,
    )
}

/// The bytes of `value` spanned by `items`, if they are exactly the joined item text.
#[expect(
    clippy::disallowed_methods,
    reason = "invalid UTF-8 only means the text is not borrowable, so the caller builds it owned"
)]
fn verbatim<'src>(value: &'src [u8], items: &[Item<'_>]) -> Option<&'src str> {
    let (first, last) = (items.first()?, items.last()?);
    if items
        .iter()
        .any(|item| item.kind == TokenKind::QuotedString)
    {
        return None;
    }
    let end = last.offset.checked_add(last.text.len())?;
    let total: usize = items.iter().map(|item| item.text.len()).sum();
    if end.checked_sub(first.offset)? != total {
        return None;
    }
    from_utf8(value.get(first.offset..end)?).ok()
}

/// Whether `item` is the `=` delimiter.
fn is_equals(item: &Item<'_>) -> bool {
    item.kind == TokenKind::Special(b'=')
}

/// Whether `item` is the `;` delimiter.
fn is_semicolon(item: &Item<'_>) -> bool {
    item.kind == TokenKind::Special(b';')
}

/// An issue for a structure the grammar does not allow, at `offset`.
const fn malformed(offset: usize) -> Issue {
    Issue::new(IssueKind::MalformedEntry, offset)
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::net::{IpAddr, Ipv4Addr};

    use super::{ReceivedSpf, SpfResult, parse_received_spf};
    use crate::caps::{Cap, MAX_ENTRIES};
    use crate::issue::{IssueKind, Parsed};

    const GREETING_KEY: &str = "helo";

    const RFC_7208: &str = concat!(
        "pass (mybox.example.org: domain of myname@example.com designates 192.0.2.1 as ",
        "permitted sender) receiver=mybox.example.org; client-ip=192.0.2.1;\r\n",
        " envelope-from=\"myname@example.com\"; helo=foo.example.com;"
    );

    const GOOGLE: &str = concat!(
        "pass (google.com: domain of sender@example.com designates 203.0.113.5 as ",
        "permitted sender) client-ip=203.0.113.5;"
    );

    const MICROSOFT: &str = concat!(
        "Pass (protection.outlook.com: domain of example.com designates 203.0.113.9 as ",
        "permitted sender) receiver=protection.outlook.com; client-ip=203.0.113.9; ",
        "helo=mail.example.com;"
    );

    const POSTFIX: &str = concat!(
        "Softfail (mailfrom) identity=mailfrom; client-ip=2001:db8::25; helo=mx.example.net; ",
        "envelope-from=bounce@example.net; receiver=<UNKNOWN>; mechanism=-all; ",
        "problem=\"no match\""
    );

    fn parse(text: &str) -> Parsed<ReceivedSpf<'_>> {
        parse_received_spf(text.as_bytes())
    }

    fn pairs<'src>(header: &'src ReceivedSpf<'_>) -> Vec<(&'src str, &'src str)> {
        header
            .pairs()
            .iter()
            .map(|pair| (&*pair.key, &*pair.value))
            .collect()
    }

    fn kinds(parsed: &Parsed<ReceivedSpf<'_>>) -> Vec<(IssueKind, usize)> {
        parsed
            .issues()
            .iter()
            .map(|issue| (issue.kind(), issue.offset()))
            .collect()
    }

    #[test]
    fn the_rfc_7208_example_recovers_result_comment_and_ordered_pairs() {
        let parsed = parse(RFC_7208);
        let header = parsed.value();
        assert_eq!(header.result(), SpfResult::Pass, "the result word");
        assert_eq!(
            header.comment(),
            Some(
                "mybox.example.org: domain of myname@example.com designates 192.0.2.1 as \
                 permitted sender"
            ),
            "the comment is kept whole"
        );
        assert_eq!(
            pairs(header),
            vec![
                ("receiver", "mybox.example.org"),
                ("client-ip", "192.0.2.1"),
                ("envelope-from", "myname@example.com"),
                (GREETING_KEY, "foo.example.com"),
            ],
            "folded pairs in header order with the quotes removed"
        );
        assert!(parsed.issues().is_empty(), "the RFC example is well formed");
    }

    #[test]
    fn a_google_header_offers_the_client_ip_as_an_address() {
        let parsed = parse(GOOGLE);
        let header = parsed.value();
        assert_eq!(header.pairs().len(), 1, "one pair");
        assert_eq!(
            header.client_ip(),
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))),
            "client-ip is parsed"
        );
        assert!(parsed.issues().is_empty(), "no issues");
    }

    #[test]
    fn a_microsoft_header_matches_the_result_ignoring_case() {
        let parsed = parse(MICROSOFT);
        let header = parsed.value();
        assert_eq!(header.result(), SpfResult::Pass, "Pass is pass");
        assert_eq!(
            pairs(header),
            vec![
                ("receiver", "protection.outlook.com"),
                ("client-ip", "203.0.113.9"),
                (GREETING_KEY, "mail.example.com"),
            ],
            "dotted values are rejoined"
        );
    }

    #[test]
    fn a_postfix_style_header_keeps_ipv6_angle_and_quoted_values() {
        let parsed = parse(POSTFIX);
        let header = parsed.value();
        assert_eq!(header.result(), SpfResult::SoftFail, "softfail");
        assert_eq!(header.comment(), Some("mailfrom"), "short comment");
        assert_eq!(
            pairs(header),
            vec![
                ("identity", "mailfrom"),
                ("client-ip", "2001:db8::25"),
                (GREETING_KEY, "mx.example.net"),
                ("envelope-from", "bounce@example.net"),
                ("receiver", "<UNKNOWN>"),
                ("mechanism", "-all"),
                ("problem", "no match"),
            ],
            "every pair including a quoted one with a space"
        );
        assert_eq!(
            header.client_ip(),
            Some("2001:db8::25".parse().expect("fixture address is valid")),
            "ipv6 is parsed"
        );
        assert!(parsed.issues().is_empty(), "no issues");
    }

    #[test]
    fn every_result_word_has_its_variant_and_an_unknown_word_is_kept() {
        let cases = [
            ("fail", SpfResult::Fail),
            ("neutral", SpfResult::Neutral),
            ("none", SpfResult::None),
            ("pass", SpfResult::Pass),
            ("permerror", SpfResult::PermError),
            ("SOFTFAIL", SpfResult::SoftFail),
            ("temperror", SpfResult::TempError),
            (
                "bestguesspass",
                SpfResult::Other(Cow::Borrowed("bestguesspass")),
            ),
        ];
        for (word, expected) in cases {
            assert_eq!(parse(word).value().result(), expected, "result {word}");
        }
    }

    #[test]
    fn unknown_keys_and_repeated_keys_are_kept_and_get_ignores_case() {
        let parsed = parse("pass x-custom=1; Client-IP=192.0.2.7; x-custom=2");
        let header = parsed.value();
        assert_eq!(
            pairs(header),
            vec![
                ("x-custom", "1"),
                ("Client-IP", "192.0.2.7"),
                ("x-custom", "2")
            ],
            "keys stay as written and repeats stay"
        );
        assert_eq!(
            header.get("CLIENT-ip").map(|pair| &*pair.value),
            Some("192.0.2.7"),
            "lookup ignores case"
        );
        assert_eq!(
            header.get("x-custom").map(|pair| &*pair.value),
            Some("1"),
            "the first repeat wins"
        );
    }

    #[test]
    fn pairs_separated_only_by_spaces_are_all_read() {
        let text = format!("pass (ok) client-ip=192.0.2.1 {GREETING_KEY}=a.example.com");
        let parsed = parse(&text);
        assert_eq!(
            pairs(parsed.value()),
            vec![("client-ip", "192.0.2.1"), (GREETING_KEY, "a.example.com")],
            "whitespace ends a value"
        );
        assert!(
            parsed.issues().is_empty(),
            "space-separated pairs are accepted"
        );
    }

    #[test]
    fn an_invalid_client_ip_stays_text_with_an_issue_at_its_key() {
        let text = format!("pass {GREETING_KEY}=a.example.com; client-ip=999.1.1.1");
        let parsed = parse(&text);
        let header = parsed.value();
        assert_eq!(header.client_ip(), None, "no address");
        assert_eq!(
            header.get("client-ip").map(|pair| &*pair.value),
            Some("999.1.1.1"),
            "the text is kept"
        );
        assert_eq!(
            kinds(&parsed),
            vec![(
                IssueKind::MalformedEntry,
                text.find("client-ip")
                    .expect("the fixture text contains a client-ip key")
            )],
            "issue at the key offset"
        );
    }

    #[test]
    fn a_key_without_a_value_is_skipped_and_later_pairs_are_kept() {
        let text = format!("pass {GREETING_KEY}=; client-ip=192.0.2.1; stray; x=y");
        let parsed = parse(&text);
        assert_eq!(
            pairs(parsed.value()),
            vec![("client-ip", "192.0.2.1"), ("x", "y")],
            "pairs around the bad segments survive"
        );
        assert_eq!(
            kinds(&parsed),
            vec![
                (IssueKind::MalformedEntry, 9),
                (IssueKind::MalformedEntry, 33)
            ],
            "one issue per bad segment at its offset"
        );
    }

    #[test]
    fn a_missing_result_is_reported_at_the_first_token() {
        let parsed = parse("client-ip=192.0.2.1");
        let header = parsed.value();
        assert_eq!(
            kinds(&parsed).first(),
            Some(&(IssueKind::MalformedEntry, 9)),
            "the equals sign is where a pair starts with no result"
        );
        assert_eq!(
            header.pairs().len(),
            0,
            "no pair can start at the equals sign"
        );
    }

    #[test]
    fn an_empty_value_yields_an_empty_result_and_one_issue() {
        let parsed = parse("");
        assert_eq!(
            parsed.value().result(),
            SpfResult::Other(Cow::Borrowed("")),
            "no result word"
        );
        assert_eq!(
            kinds(&parsed),
            vec![(IssueKind::MalformedEntry, 0)],
            "issue at the end"
        );
    }

    #[test]
    fn pairs_past_the_cap_are_dropped_and_reported_once() {
        let mut text = String::from("pass");
        text.push_str(&"; k=v".repeat(MAX_ENTRIES + 5));
        let parsed = parse(&text);
        assert_eq!(
            parsed.value().pairs().len(),
            MAX_ENTRIES,
            "capped pair count"
        );
        let caps = parsed
            .issues()
            .iter()
            .filter(|issue| issue.kind() == IssueKind::CapExceeded { cap: Cap::Entries })
            .count();
        assert_eq!(caps, 1, "one CapExceeded issue");
    }

    #[test]
    fn an_unterminated_comment_is_reported_and_the_result_is_kept() {
        let parsed = parse("pass (open comment");
        assert_eq!(parsed.value().result(), SpfResult::Pass, "result survives");
        assert_eq!(
            kinds(&parsed),
            vec![(IssueKind::UnterminatedComment, 5)],
            "tokenizer issue is included"
        );
    }
}
