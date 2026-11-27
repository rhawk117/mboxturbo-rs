//! Parser for `Authentication-Results` header values (RFC 8601) and Microsoft's variants.
//!
//! One pass over the shared tokens: the value is cut at `;` into the authserv-id segment and
//! one segment per result, and each segment is read as `name=value` pairs. Tokens that touch
//! with no whitespace or comment between them form one word, which is how `header.from` and
//! `user@example.com` are put back together from the tokenizer's atoms and delimiters.

use std::borrow::Cow;
use std::str::from_utf8;

use crate::caps::{Cap, MAX_ENTRIES};
use crate::issue::{Issue, IssueKind, Parsed};
use crate::tokenize::{Token, TokenKind, tokenize};
use crate::trust::TrustSet;

/// Authentication methods with a dedicated variant, matched ASCII case-insensitively.
static METHODS: [(&str, AuthMethod<'static>); 9] = [
    ("arc", AuthMethod::Arc),
    ("auth", AuthMethod::Auth),
    ("compauth", AuthMethod::CompAuth),
    ("dkim", AuthMethod::Dkim),
    ("dmarc", AuthMethod::Dmarc),
    ("domainkeys", AuthMethod::DomainKeys),
    ("iprev", AuthMethod::Iprev),
    ("sender-id", AuthMethod::SenderId),
    ("spf", AuthMethod::Spf),
];

/// Results with a dedicated variant, matched ASCII case-insensitively.
static RESULTS: [(&str, AuthResult<'static>); 10] = [
    ("fail", AuthResult::Fail),
    ("hardfail", AuthResult::Fail),
    ("neutral", AuthResult::Neutral),
    ("none", AuthResult::NoResult),
    ("pass", AuthResult::Pass),
    ("permerror", AuthResult::PermError),
    ("policy", AuthResult::Policy),
    ("softfail", AuthResult::SoftFail),
    ("temperror", AuthResult::TempError),
    ("unknown", AuthResult::Unknown),
];

/// An authentication method named in a result.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthMethod<'src> {
    /// `arc`, the authenticated received chain.
    Arc,
    /// `auth`, SMTP authentication.
    Auth,
    /// `compauth`, Microsoft's composite authentication verdict.
    CompAuth,
    /// `dkim`.
    Dkim,
    /// `dmarc`.
    Dmarc,
    /// `domainkeys`.
    DomainKeys,
    /// `iprev`, the reverse DNS check.
    Iprev,
    /// A method with no variant of its own, kept as written.
    Other(Cow<'src, str>),
    /// `sender-id`.
    SenderId,
    /// `spf`.
    Spf,
}

/// The outcome a method reported.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthResult<'src> {
    /// `fail`, and the older `hardfail`.
    Fail,
    /// `neutral`.
    Neutral,
    /// `none`, the method ran but found nothing to check.
    NoResult,
    /// A result with no variant of its own, such as `bestguesspass`, kept as written.
    Other(Cow<'src, str>),
    /// `pass`.
    Pass,
    /// `permerror`, a permanent evaluation error.
    PermError,
    /// `policy`, the verdict was withheld by local policy.
    Policy,
    /// `softfail`.
    SoftFail,
    /// `temperror`, a temporary evaluation error.
    TempError,
    /// `unknown`, the method could not be evaluated.
    Unknown,
}

impl<'src> AuthMethod<'src> {
    /// Maps a method name to its variant, keeping an unknown name verbatim.
    fn from_name(name: Cow<'src, str>) -> Self {
        METHODS
            .iter()
            .find(|(known, _)| known.eq_ignore_ascii_case(&name))
            .map_or(Self::Other(name), |(_, method)| method.clone())
    }

    /// The method name as written in the header: lowercase for a method with a variant of its
    /// own, verbatim for any other.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Arc => "arc",
            Self::Auth => "auth",
            Self::CompAuth => "compauth",
            Self::Dkim => "dkim",
            Self::Dmarc => "dmarc",
            Self::DomainKeys => "domainkeys",
            Self::Iprev => "iprev",
            Self::Other(name) => name,
            Self::SenderId => "sender-id",
            Self::Spf => "spf",
        }
    }
}

impl<'src> AuthResult<'src> {
    /// Maps a result name to its variant, keeping an unknown name verbatim.
    fn from_name(name: Cow<'src, str>) -> Self {
        RESULTS
            .iter()
            .find(|(known, _)| known.eq_ignore_ascii_case(&name))
            .map_or(Self::Other(name), |(_, result)| result.clone())
    }

    /// The result word as written in the header: lowercase for a result with a variant of its
    /// own (`hardfail` reads `fail`), verbatim for any other.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Fail => "fail",
            Self::Neutral => "neutral",
            Self::NoResult => "none",
            Self::Other(name) => name,
            Self::Pass => "pass",
            Self::PermError => "permerror",
            Self::Policy => "policy",
            Self::SoftFail => "softfail",
            Self::TempError => "temperror",
            Self::Unknown => "unknown",
        }
    }
}

/// Whether the header's authserv-id is in the caller's trust set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TrustStatus {
    /// A trust set was given and holds the authserv-id.
    Trusted,
    /// No trust set was given, so nothing can be said.
    Unknown,
    /// A trust set was given and lacks the authserv-id, or the header has none.
    Untrusted,
}

/// A `ptype.property=value` pair of a result, such as `header.from=example.com`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthProperty<'src> {
    /// The part after the first dot, or the whole name when there is no dot.
    property: Cow<'src, str>,
    /// The part before the first dot, empty for tokens such as Microsoft's `action=none`.
    ptype: Cow<'src, str>,
    /// The value, with quotes removed.
    value: Cow<'src, str>,
}

impl AuthProperty<'_> {
    /// The part after the first dot, or the whole name when there is no dot.
    #[must_use]
    pub fn property(&self) -> &str {
        &self.property
    }

    /// The part before the first dot, empty for a name with no dot.
    #[must_use]
    pub fn ptype(&self) -> &str {
        &self.ptype
    }

    /// The value, with quotes removed.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// One method's result with its reason and properties.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResInfo<'src> {
    /// The method that ran.
    method: AuthMethod<'src>,
    /// The properties after the result, in header order.
    properties: Vec<AuthProperty<'src>>,
    /// The text of the first `reason=` pair, if any.
    reason: Option<Cow<'src, str>>,
    /// What the method reported.
    result: AuthResult<'src>,
}

impl<'src> ResInfo<'src> {
    /// Files one pair after the result as the reason or as a property.
    fn add_pair(&mut self, value: &'src [u8], pair: &Pair<'_, '_>) {
        let text = join(value, pair.value);
        if self.reason.is_none() && is_word(pair.key, "reason") {
            self.reason = Some(text);
            return;
        }
        let (ptype, property) = split_key(pair.key);
        self.properties.push(AuthProperty {
            ptype: join(value, ptype),
            property: join(value, property),
            value: text,
        });
    }

    /// Files each pair of `rest` in turn; a pair that cannot be read ends the segment.
    fn add_pairs(&mut self, value: &'src [u8], mut rest: &[Item<'_>], issues: &mut Vec<Issue>) {
        while !rest.is_empty() {
            match take_pair(rest) {
                Ok((pair, next)) => {
                    self.add_pair(value, &pair);
                    rest = next;
                },
                Err(offset) => {
                    issues.push(malformed(offset));
                    return;
                },
            }
        }
    }

    /// The method that ran; a version suffix such as `dkim/1` is dropped.
    #[must_use]
    pub const fn method(&self) -> &AuthMethod<'src> {
        &self.method
    }

    /// The properties after the result, in header order; a repeated `reason` is kept here.
    #[must_use]
    pub fn properties(&self) -> &[AuthProperty<'src>] {
        &self.properties
    }

    /// The text of the first `reason=` pair, if any.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    /// What the method reported.
    #[must_use]
    pub const fn result(&self) -> &AuthResult<'src> {
        &self.result
    }
}

/// A parsed `Authentication-Results` header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationResults<'src> {
    /// The identity of the host that wrote the header, empty when the value starts directly
    /// with a result as Microsoft's headers do.
    authserv_id: Cow<'src, str>,
    /// The results in header order; `none` as the whole body gives an empty list.
    entries: Vec<ResInfo<'src>>,
    /// Whether the caller's trust set vouches for the authserv-id.
    trust: TrustStatus,
    /// The version number after the authserv-id, if present.
    version: Option<u32>,
}

impl<'src> AuthenticationResults<'src> {
    /// The identity of the host that wrote the header, empty when the value starts directly
    /// with a result as Microsoft's headers do.
    #[must_use]
    pub fn authserv_id(&self) -> &str {
        &self.authserv_id
    }

    /// The results in header order; `none` as the whole body gives an empty list.
    #[must_use]
    pub fn entries(&self) -> &[ResInfo<'src>] {
        &self.entries
    }

    /// Whether the caller's trust set vouches for the authserv-id. A header whose id is
    /// outside the set is [`TrustStatus::Untrusted`] whatever it claims, so a forged `pass`
    /// from an outside host is never taken at face value.
    #[must_use]
    pub const fn trust(&self) -> TrustStatus {
        self.trust
    }

    /// The version number after the authserv-id, if present.
    #[must_use]
    pub const fn version(&self) -> Option<u32> {
        self.version
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

/// A `key=value` pair; both sides are runs of items.
struct Pair<'run, 'tok> {
    /// The items before the `=`.
    key: &'run [Item<'tok>],
    /// The items after the `=` that touch each other.
    value: &'run [Item<'tok>],
}

/// A pair and the items after it, or the byte offset where no pair could be read.
type Taken<'run, 'tok> = Result<(Pair<'run, 'tok>, &'run [Item<'tok>]), usize>;

/// Reads `value` as an `Authentication-Results` body.
///
/// `trust` is the caller's trust set. With it the result is [`TrustStatus::Trusted`] or
/// [`TrustStatus::Untrusted`] by authserv-id; without it, [`TrustStatus::Unknown`]. Comments
/// are skipped and quoted values are unquoted. A body of `none` yields no entries. Anything
/// the grammar does not allow is reported as [`IssueKind::MalformedEntry`] at its byte offset
/// and the entries read before it are kept; more than [`MAX_ENTRIES`] entries are dropped and
/// reported once as [`IssueKind::CapExceeded`]. Tokenizer issues are included. Work is linear
/// in the length of `value`.
#[must_use]
pub fn parse_authentication_results<'src>(
    value: &'src [u8],
    trust: Option<&TrustSet>,
) -> Parsed<AuthenticationResults<'src>> {
    let (tokens, mut issues) = tokenize(value).into_parts();
    let items = items(value, &tokens);
    let head_len = items.iter().position(is_semicolon).unwrap_or(items.len());
    let (head, tail) = items.split_at(head_len);
    let direct = head.iter().any(is_equals);
    let (authserv_id, version) = if direct {
        (Cow::Borrowed(""), None)
    } else {
        parse_head(value, head, tail.first(), &mut issues)
    };
    if !direct && tail.is_empty() && !head.is_empty() {
        issues.push(malformed(value.len()));
    }
    let skip = usize::from(!direct);
    let entries = parse_entries(value, if direct { &items } else { tail }, skip, &mut issues);
    issues.sort_by_key(Issue::offset);
    let status = trust_status(trust, &authserv_id);
    let results = AuthenticationResults {
        authserv_id,
        entries,
        trust: status,
        version,
    };
    Parsed::new(results, issues)
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

/// Reads the authserv-id and optional version in front of the first `;`.
fn parse_head<'src>(
    value: &'src [u8],
    head: &[Item<'_>],
    semicolon: Option<&Item<'_>>,
    issues: &mut Vec<Issue>,
) -> (Cow<'src, str>, Option<u32>) {
    let (id, rest) = head.split_at(word_len(head, |_| true));
    if id.is_empty() {
        issues.push(malformed(semicolon.map_or(value.len(), |item| item.offset)));
    }
    let Some((first, after)) = rest.split_first() else {
        return (join(value, id), None);
    };
    let Ok(version) = first.text.parse::<u32>() else {
        issues.push(malformed(first.offset));
        return (join(value, id), None);
    };
    if let Some(extra) = after.first() {
        issues.push(malformed(extra.offset));
    }
    (join(value, id), Some(version))
}

/// Reads each `;`-separated segment of `items` after the first `skip` as one result.
fn parse_entries<'src>(
    value: &'src [u8],
    items: &[Item<'_>],
    skip: usize,
    issues: &mut Vec<Issue>,
) -> Vec<ResInfo<'src>> {
    let mut entries = Vec::new();
    for segment in items.split(is_semicolon).skip(skip) {
        let Some(first) = segment.first() else {
            continue;
        };
        if is_word(segment, "none") {
            continue;
        }
        if entries.len() >= MAX_ENTRIES {
            let cap = Issue::new(IssueKind::CapExceeded { cap: Cap::Entries }, first.offset);
            issues.push(cap);
            break;
        }
        entries.extend(parse_res_info(value, segment, issues));
    }
    entries
}

/// Reads one segment as `method=result` followed by pairs; a bad pair ends the segment.
fn parse_res_info<'src>(
    value: &'src [u8],
    segment: &[Item<'_>],
    issues: &mut Vec<Issue>,
) -> Option<ResInfo<'src>> {
    let (head, rest) = match take_pair(segment) {
        Ok(taken) => taken,
        Err(offset) => {
            issues.push(malformed(offset));
            return None;
        },
    };
    let name = head
        .key
        .split(is_slash)
        .next()
        .map_or(head.key, |name| name);
    let mut info = ResInfo {
        method: AuthMethod::from_name(join(value, name)),
        properties: Vec::new(),
        reason: None,
        result: AuthResult::from_name(join(value, head.value)),
    };
    info.add_pairs(value, rest, issues);
    Some(info)
}

/// Splits one `key=value` pair off the front of `items`, or gives the offset of the problem.
fn take_pair<'run, 'tok>(items: &'run [Item<'tok>]) -> Taken<'run, 'tok> {
    let (key, rest) = items.split_at(word_len(items, |item| !is_equals(item)));
    let Some((equals, after)) = rest.split_first().filter(|(item, _)| is_equals(item)) else {
        return Err(items.first().map_or(0, |item| item.offset));
    };
    if key.is_empty() || after.is_empty() {
        return Err(equals.offset);
    }
    let (value, next) = after.split_at(word_len(after, |_| true));
    Ok((Pair { key, value }, next))
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

/// Splits a key at its first `.` into the ptype items and the property items.
fn split_key<'run, 'tok>(key: &'run [Item<'tok>]) -> (&'run [Item<'tok>], &'run [Item<'tok>]) {
    let Some(dot) = key.iter().position(is_dot) else {
        return (&[], key);
    };
    let (ptype, from_dot) = key.split_at(dot);
    (
        ptype,
        from_dot.split_first().map_or(from_dot, |(_, tail)| tail),
    )
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

/// Whether `items` is exactly one atom equal to `word`, ignoring ASCII case.
fn is_word(items: &[Item<'_>], word: &str) -> bool {
    matches!(items, [only] if only.kind == TokenKind::Atom && only.text.eq_ignore_ascii_case(word))
}

/// Whether `item` is the `.` delimiter.
fn is_dot(item: &Item<'_>) -> bool {
    item.kind == TokenKind::Special(b'.')
}

/// Whether `item` is the `=` delimiter.
fn is_equals(item: &Item<'_>) -> bool {
    item.kind == TokenKind::Special(b'=')
}

/// Whether `item` is the `;` delimiter.
fn is_semicolon(item: &Item<'_>) -> bool {
    item.kind == TokenKind::Special(b';')
}

/// Whether `item` is the `/` delimiter.
fn is_slash(item: &Item<'_>) -> bool {
    item.kind == TokenKind::Special(b'/')
}

/// An issue for a structure the grammar does not allow, at `offset`.
const fn malformed(offset: usize) -> Issue {
    Issue::new(IssueKind::MalformedEntry, offset)
}

/// Decides the trust status of `authserv_id` against an optional trust set.
fn trust_status(trust: Option<&TrustSet>, authserv_id: &str) -> TrustStatus {
    match trust {
        None => TrustStatus::Unknown,
        Some(set) if set.trusts_authserv_id(authserv_id.as_bytes()) => TrustStatus::Trusted,
        Some(_) => TrustStatus::Untrusted,
    }
}

#[cfg(test)]
#[expect(
    unused_results,
    reason = "the trust set builder methods return &mut Self for chaining, which tests ignore"
)]
mod tests {
    use std::borrow::Cow;
    use std::iter::repeat_n;

    use super::{
        AuthMethod, AuthResult, AuthenticationResults, METHODS, RESULTS, ResInfo, TrustStatus,
        parse_authentication_results,
    };
    use crate::caps::{Cap, MAX_ENTRIES};
    use crate::issue::{IssueKind, Parsed};
    use crate::trust::TrustSet;

    const MEBIBYTE: usize = 1 << 20;

    const MICROSOFT: &str = concat!(
        "spf=pass (sender IP is 192.0.2.1) smtp.mailfrom=example.com;",
        " dkim=pass (signature was verified) header.d=example.com;",
        " dmarc=pass action=none header.from=example.com;",
        " compauth=pass reason=100"
    );

    const RFC_B2: &str = concat!(
        "example.com;\r\n sender-id=fail header.from=example.com;\r\n",
        " dkim=pass (good signature) header.d=example.com"
    );

    fn parse(text: &str) -> Parsed<AuthenticationResults<'_>> {
        parse_authentication_results(text.as_bytes(), None)
    }

    fn props(entry: &ResInfo<'_>) -> Vec<(String, String, String)> {
        entry
            .properties()
            .iter()
            .map(|prop| {
                (
                    prop.ptype().to_owned(),
                    prop.property().to_owned(),
                    prop.value().to_owned(),
                )
            })
            .collect()
    }

    fn triple(ptype: &str, property: &str, value: &str) -> (String, String, String) {
        (ptype.to_owned(), property.to_owned(), value.to_owned())
    }

    fn kinds(parsed: &Parsed<AuthenticationResults<'_>>) -> Vec<(IssueKind, usize)> {
        parsed
            .issues()
            .iter()
            .map(|issue| (issue.kind(), issue.offset()))
            .collect()
    }

    #[test]
    fn none_as_the_whole_body_yields_no_entries_and_the_version() {
        let parsed = parse("example.org 1; none");
        let header = parsed.value();
        assert_eq!(header.authserv_id(), "example.org", "dotted id is rejoined");
        assert_eq!(header.version(), Some(1), "version follows the id");
        assert!(header.entries().is_empty(), "none is not an entry");
        assert!(parsed.issues().is_empty(), "RFC 8601 B.1 is well formed");
    }

    #[test]
    fn rfc_8601_b2_recovers_a_failing_sender_id_with_its_property() {
        let parsed = parse(RFC_B2);
        let entries = parsed.value().entries();
        assert_eq!(entries.len(), 2, "two results");
        assert_eq!(entries[0].method(), &AuthMethod::SenderId, "first method");
        assert_eq!(entries[0].result(), &AuthResult::Fail, "first result");
        assert_eq!(
            props(&entries[0]),
            vec![triple("header", "from", "example.com")],
            "folded property"
        );
        assert!(parsed.issues().is_empty(), "B.2 is well formed");
    }

    #[test]
    fn rfc_8601_b2_skips_the_comment_after_a_passing_dkim_result() {
        let parsed = parse(RFC_B2);
        let entry = &parsed.value().entries()[1];
        assert_eq!(entry.method(), &AuthMethod::Dkim, "second method");
        assert_eq!(entry.result(), &AuthResult::Pass, "the comment is skipped");
        assert_eq!(
            props(entry),
            vec![triple("header", "d", "example.com")],
            "property after the comment"
        );
    }

    #[test]
    fn a_quoted_reason_and_an_at_value_are_recovered() {
        let text = concat!(
            "foo.example.net (foobar) 1 (baz); dkim=pass reason=\"good signature\"",
            " header.i=@mail-router.example.net"
        );
        let parsed = parse(text);
        let header = parsed.value();
        assert_eq!(
            header.authserv_id(),
            "foo.example.net",
            "comments are skipped"
        );
        assert_eq!(header.version(), Some(1), "version after a comment");
        let entry = &header.entries()[0];
        assert_eq!(entry.reason(), Some("good signature"), "quotes are removed");
        assert_eq!(
            props(entry),
            vec![triple("header", "i", "@mail-router.example.net")],
            "the reason is not a property and @ joins the value"
        );
    }

    #[test]
    fn a_method_version_is_dropped_and_names_match_ignoring_case() {
        let parsed = parse("mx.example.org; DKIM/1=PASS header.d=example.org");
        let entry = &parsed.value().entries()[0];
        assert_eq!(entry.method(), &AuthMethod::Dkim, "version suffix removed");
        assert_eq!(entry.result(), &AuthResult::Pass, "case-insensitive result");
    }

    #[test]
    fn a_microsoft_header_without_an_authserv_id_reads_its_first_result() {
        let parsed = parse(MICROSOFT);
        let header = parsed.value();
        assert_eq!(header.authserv_id(), "", "no authserv-id");
        assert_eq!(header.entries().len(), 4, "four results");
        assert_eq!(
            props(&header.entries()[0]),
            vec![triple("smtp", "mailfrom", "example.com")],
            "the comment with an IP is skipped"
        );
        assert!(parsed.issues().is_empty(), "known shape is not an issue");
    }

    #[test]
    fn microsoft_action_is_a_property_with_an_empty_ptype() {
        let parsed = parse(MICROSOFT);
        let dmarc = &parsed.value().entries()[2];
        assert_eq!(dmarc.method(), &AuthMethod::Dmarc, "dmarc method");
        assert_eq!(
            props(dmarc),
            vec![
                triple("", "action", "none"),
                triple("header", "from", "example.com")
            ],
            "action has an empty ptype"
        );
    }

    #[test]
    fn microsoft_compauth_carries_a_numeric_reason() {
        let parsed = parse(MICROSOFT);
        let compauth = &parsed.value().entries()[3];
        assert_eq!(compauth.method(), &AuthMethod::CompAuth, "compauth method");
        assert_eq!(compauth.reason(), Some("100"), "numeric reason");
    }

    #[test]
    fn vendor_methods_and_results_are_kept_verbatim() {
        let parsed = parse("mx.example.org; x-vendor=bestguesspass");
        let entry = &parsed.value().entries()[0];
        assert_eq!(
            entry.method(),
            &AuthMethod::Other(Cow::Borrowed("x-vendor")),
            "unknown method kept"
        );
        assert_eq!(
            entry.result(),
            &AuthResult::Other(Cow::Borrowed("bestguesspass")),
            "unknown result kept"
        );
    }

    #[test]
    fn trust_follows_the_authserv_id_and_a_forged_pass_stays_untrusted() {
        let mut set = TrustSet::new();
        set.add_authserv_id("mx.example.org");
        let trusted = parse_authentication_results(b"MX.example.org; spf=pass", Some(&set));
        assert_eq!(
            trusted.value().trust(),
            TrustStatus::Trusted,
            "id in the set"
        );
        let forged = parse_authentication_results(b"evil.example; spf=pass", Some(&set));
        assert_eq!(
            forged.value().trust(),
            TrustStatus::Untrusted,
            "id outside the set"
        );
        assert_eq!(
            forged.value().entries()[0].result(),
            &AuthResult::Pass,
            "claims pass"
        );
        let unknown = parse("mx.example.org; spf=pass");
        assert_eq!(
            unknown.value().trust(),
            TrustStatus::Unknown,
            "no trust set"
        );
    }

    #[test]
    fn a_result_without_an_equals_is_reported_and_earlier_entries_are_kept() {
        let parsed = parse("mx.example.org; spf=pass; garbage here");
        assert_eq!(parsed.value().entries().len(), 1, "the good entry survives");
        assert_eq!(
            kinds(&parsed),
            vec![(IssueKind::MalformedEntry, 26)],
            "issue at the offending word"
        );
    }

    #[test]
    fn a_bad_property_keeps_the_method_and_result() {
        let parsed = parse("mx.example.org; spf=pass header.d=a stray");
        let entry = &parsed.value().entries()[0];
        assert_eq!(
            props(entry),
            vec![triple("header", "d", "a")],
            "pairs before the stray"
        );
        assert_eq!(
            kinds(&parsed),
            vec![(IssueKind::MalformedEntry, 36)],
            "issue at stray"
        );
    }

    #[test]
    fn empty_and_garbage_input_gives_issues_and_no_entries() {
        for text in ["", ";", "garbage", "= = =", "(", "\"x", ";;;"] {
            let parsed = parse(text);
            assert!(
                parsed.value().entries().is_empty(),
                "{text:?} has no entries"
            );
        }
        assert_eq!(
            kinds(&parse("")),
            vec![(IssueKind::MalformedEntry, 0)],
            "empty value"
        );
        assert_eq!(
            kinds(&parse("garbage")),
            vec![(IssueKind::MalformedEntry, 7)],
            "an id with no results"
        );
    }

    #[test]
    fn entries_past_the_cap_are_dropped_and_reported_once() {
        let mut text = String::from("mx.example.org");
        text.extend(repeat_n("; spf=pass", MAX_ENTRIES + 5));
        let parsed = parse(&text);
        assert_eq!(
            parsed.value().entries().len(),
            MAX_ENTRIES,
            "kept up to the cap"
        );
        let caps = parsed
            .issues()
            .iter()
            .filter(|issue| matches!(issue.kind(), IssueKind::CapExceeded { cap: Cap::Entries }))
            .count();
        assert_eq!(caps, 1, "reported once, got {:?}", parsed.issues());
    }

    #[test]
    fn a_one_mebibyte_value_of_results_is_capped_at_the_entry_limit() {
        let mut text = String::from("mx.example.org");
        while text.len() < MEBIBYTE {
            text.push_str("; a=b header.x=yyyy");
        }
        let parsed = parse(&text);
        assert_eq!(parsed.value().entries().len(), MAX_ENTRIES, "capped");
    }

    #[test]
    fn a_one_mebibyte_atom_is_an_id_with_no_results() {
        let long = "x".repeat(MEBIBYTE);
        let parsed = parse(&long);
        assert!(
            parsed.value().entries().is_empty(),
            "one huge atom has no entries"
        );
        assert!(
            !parsed.issues().is_empty(),
            "the missing results are reported"
        );
    }

    #[test]
    fn every_method_and_result_with_a_variant_names_itself_as_the_table_spells_it() {
        for (word, method) in &METHODS {
            assert_eq!(method.name(), *word, "method {word} names itself");
        }
        for (word, result) in RESULTS.iter().filter(|(word, _)| *word != "hardfail") {
            assert_eq!(result.name(), *word, "result {word} names itself");
        }
        assert_eq!(AuthResult::Fail.name(), "fail", "hardfail reads fail");
    }

    #[test]
    fn a_method_or_result_without_a_variant_names_itself_as_written() {
        assert_eq!(
            AuthMethod::Other(Cow::Borrowed("x-custom")).name(),
            "x-custom",
            "method kept verbatim"
        );
        assert_eq!(
            AuthResult::Other(Cow::Borrowed("bestguesspass")).name(),
            "bestguesspass",
            "result kept verbatim"
        );
    }
}
