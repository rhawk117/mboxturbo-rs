//! Parser for the `Received` headers of a message (RFC 5321 section 4.4).
//!
//! Each header is tokenized once. The text before the first top-level `;` is cut into words
//! and comments (touching atoms and delimiters such as `<user@example.com>` or
//! `[192.0.2.1]` form one word), the words are sorted into the `from`, `by`, `with`, `id` and
//! `for` clauses, and the text after the `;` is the date. The hops are then put in path
//! order and each is compared with the one before it.

use std::borrow::Cow;
use std::net::IpAddr;
use std::ops::Range;
use std::str::from_utf8;

use crate::caps::{Cap, MAX_RECEIVED_HOPS};
use crate::date::{Instant, parse_date};
use crate::issue::{Issue, IssueKind, Parsed};
use crate::tokenize::{Token, TokenKind, bound, tokenize};
use crate::trust::TrustSet;

/// Clause keywords, matched ASCII case-insensitively. `via` names a clause nothing reads.
static KEYWORDS: [(&str, Clause); 6] = [
    ("by", Clause::By),
    ("for", Clause::For),
    ("from", Clause::From),
    ("id", Clause::Id),
    ("via", Clause::Other),
    ("with", Clause::With),
];

/// The clause a run of words belongs to.
#[derive(Debug, Clone, Copy)]
enum Clause {
    /// `by`, the receiving host.
    By,
    /// `for`, the envelope recipient.
    For,
    /// `from`, the sending host.
    From,
    /// `id`, the receiver's queue id.
    Id,
    /// Words before the first keyword and the `via` clause, which nothing reads.
    Other,
    /// `with`, the protocol.
    With,
}

/// Whether an [`Item`] is a parenthesised comment or a word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ItemKind {
    /// A parenthesised comment, text without the outer parentheses.
    Comment,
    /// An atom, quoted string or run of touching atoms and delimiters.
    Word,
}

/// Where a hop's client address was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressSource {
    /// A `[literal]` word, which Postfix, Sendmail and Exchange fill with the HELO the client
    /// sent, so the sender chose it.
    Claimed,
    /// A `from` comment, where the receiving MTA writes the address it accepted the
    /// connection from. Only this source can make a sender trusted.
    Recorded,
}

/// The TLS details a receiver wrote in a comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tls<'src> {
    /// The cipher suite, when the comment names one.
    cipher: Option<Cow<'src, str>>,
    /// The protocol version, such as `TLSv1.3` or `TLS1_2`.
    version: Cow<'src, str>,
}

impl Tls<'_> {
    /// The cipher suite, when the comment names one.
    #[must_use]
    pub fn cipher(&self) -> Option<&str> {
        self.cipher.as_deref()
    }

    /// The protocol version as written, such as `TLSv1.3` or `TLS1_2`.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }
}

/// One `Received` header read into its parts. Every part is absent when the header does not
/// carry it; a header with none of them (`(qmail 4242 invoked by uid 1000)`) still makes a hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hop<'src> {
    /// The first word after `by`.
    by_host: Option<Cow<'src, str>>,
    /// The date after the `;`, when it could be read.
    date: Option<Instant>,
    /// Seconds from the previous hop's date to this one's; set when both dates were read.
    delay_seconds: Option<i64>,
    /// The first comment after `from`, usually the helo name and reverse lookup.
    from_comment: Option<Cow<'src, str>>,
    /// The first word after `from`.
    from_host: Option<Cow<'src, str>>,
    /// Position of this hop's header in the slice given to [`parse_received_hops`].
    header_index: usize,
    /// The first word after `id`.
    id: Option<Cow<'src, str>>,
    /// The client address read from the `from` clause, and whether the receiver recorded it.
    ip: Option<(IpAddr, AddressSource)>,
    /// The words after `with`, joined by single spaces.
    protocol: Option<Cow<'src, str>>,
    /// The first word after `for`, without angle brackets.
    recipient: Option<Cow<'src, str>>,
    /// Byte offset of the `;` in the header, or the header length when there is none.
    semicolon: usize,
    /// The TLS details from the first comment that has a version.
    tls: Option<Tls<'src>>,
}

impl Hop<'_> {
    /// The host after `by`, the machine that wrote this header.
    #[must_use]
    pub fn by_host(&self) -> Option<&str> {
        self.by_host.as_deref()
    }

    /// The date after the `;`. `None` when it is missing or could not be read.
    #[must_use]
    pub const fn date(&self) -> Option<Instant> {
        self.date
    }

    /// Seconds between the previous hop's date and this one's, negative when this hop claims to
    /// be earlier. `None` for the oldest hop and when either date could not be read.
    #[must_use]
    pub const fn delay_seconds(&self) -> Option<i64> {
        self.delay_seconds
    }

    /// The first comment of the `from` clause, such as `mail.example.org [192.0.2.10]`.
    #[must_use]
    #[expect(
        clippy::wrong_self_convention,
        reason = "the accessor is named for the `from` clause it reads"
    )]
    pub fn from_comment(&self) -> Option<&str> {
        self.from_comment.as_deref()
    }

    /// The `from` host as the sender introduced itself; a domain literal keeps its brackets.
    #[must_use]
    #[expect(
        clippy::wrong_self_convention,
        reason = "the accessor is named for the `from` clause it reads"
    )]
    pub fn from_host(&self) -> Option<&str> {
        self.from_host.as_deref()
    }

    /// Position of this hop's header in the slice given to [`parse_received_hops`], which is
    /// newest first.
    #[must_use]
    pub const fn header_index(&self) -> usize {
        self.header_index
    }

    /// The queue id after `id`.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    /// The client address: the one the receiver recorded in a `from` comment (in its
    /// `[brackets]`, or a comment that is only an address), else a `[address]` word, which is
    /// the address the client claimed in its HELO. A bracketed address tagged `helo=` and a
    /// qmail `(HELO ...)` comment are claims too and never the recorded address. An `IPv6:`
    /// prefix is accepted.
    #[must_use]
    pub const fn ip(&self) -> Option<IpAddr> {
        match self.ip {
            Some((ip, _)) => Some(ip),
            None => None,
        }
    }

    /// The protocol words after `with`, such as `ESMTPS` or `Microsoft SMTP Server`.
    #[must_use]
    pub fn protocol(&self) -> Option<&str> {
        self.protocol.as_deref()
    }

    /// The recipient after `for`, without the angle brackets.
    #[must_use]
    pub fn recipient(&self) -> Option<&str> {
        self.recipient.as_deref()
    }

    /// The TLS version and cipher, read from the comment Postfix (`using TLSv1.3 with cipher
    /// X`), Microsoft (`version=TLS1_2, cipher=X`) or Google (`version=TLS1_3 cipher=X`) write.
    #[must_use]
    pub const fn tls(&self) -> Option<&Tls<'_>> {
        self.tls.as_ref()
    }
}

/// The hops of a message in path order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedHops<'src> {
    /// Index into `hops` of the first external hop.
    first_external: Option<usize>,
    /// The hops, oldest first.
    hops: Vec<Hop<'src>>,
}

impl<'src> ReceivedHops<'src> {
    /// Index into [`Self::hops`] of the first external hop: the newest hop whose `by` host is
    /// trusted and whose sender is not, judged by the address the receiver recorded (see
    /// [`parse_received_hops`]). `None` without a trust set or when no hop qualifies.
    #[must_use]
    pub const fn first_external(&self) -> Option<usize> {
        self.first_external
    }

    /// The hops, oldest first, so the last one is the newest.
    #[must_use]
    pub fn hops(&self) -> &[Hop<'src>] {
        &self.hops
    }
}

/// One comment or word of a header, with where it starts.
#[derive(Debug)]
struct Item<'src> {
    /// Whether this is a comment or a word.
    kind: ItemKind,
    /// Byte offset of the item in the header, at the opening delimiter for comments.
    offset: usize,
    /// The decoded text.
    text: Cow<'src, str>,
}

/// The items of each clause, in header order.
#[derive(Debug, Default)]
struct Clauses<'item, 'src> {
    /// Items after `by`.
    by: Vec<&'item Item<'src>>,
    /// Items after `for`.
    for_clause: Vec<&'item Item<'src>>,
    /// Items after `from`.
    from: Vec<&'item Item<'src>>,
    /// Items after `id`.
    id: Vec<&'item Item<'src>>,
    /// Items nothing reads.
    other: Vec<&'item Item<'src>>,
    /// Items after `with`.
    with: Vec<&'item Item<'src>>,
}

impl<'item, 'src> Clauses<'item, 'src> {
    /// Sorts `items` into clauses; a word that is a keyword starts the next clause.
    fn collect(items: &'item [Item<'src>]) -> Self {
        let mut clauses = Self::default();
        let mut current = Clause::Other;
        for item in items {
            match keyword(item) {
                Some(next) => current = next,
                None => clauses.slot(current).push(item),
            }
        }
        clauses
    }

    /// The list that holds the items of `clause`.
    const fn slot(&mut self, clause: Clause) -> &mut Vec<&'item Item<'src>> {
        match clause {
            Clause::By => &mut self.by,
            Clause::For => &mut self.for_clause,
            Clause::From => &mut self.from,
            Clause::Id => &mut self.id,
            Clause::Other => &mut self.other,
            Clause::With => &mut self.with,
        }
    }
}

/// The clause a keyword word opens, or `None` for any other item.
fn keyword(item: &Item<'_>) -> Option<Clause> {
    if item.kind != ItemKind::Word {
        return None;
    }
    KEYWORDS
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(&item.text))
        .map(|&(_, clause)| clause)
}

/// Whether `token` is a plain atom or delimiter that can join a neighbour into one word.
const fn is_plain(token: &Token<'_>) -> bool {
    matches!(token.kind(), TokenKind::Atom | TokenKind::Special(_))
}

/// Whether `next` starts exactly where `prev` ends and both are plain.
fn joins(prev: &Token<'_>, next: &Token<'_>) -> bool {
    is_plain(prev)
        && is_plain(next)
        && prev.offset().checked_add(prev.text().len()) == Some(next.offset())
}

/// Whether the concatenation of `parts` is exactly `raw`.
fn is_concat<'tok>(raw: &str, parts: impl Iterator<Item = &'tok str>) -> bool {
    let mut rest = raw;
    for part in parts {
        let Some(after) = rest.strip_prefix(part) else {
            return false;
        };
        rest = after;
    }
    rest.is_empty()
}

/// The concatenation of `parts`, borrowed from `value` at `start` when the bytes there are
/// exactly that text and copied when unfolding or lossy decoding changed it.
fn source_text<'src, 'tok>(
    value: &'src [u8],
    start: usize,
    parts: impl Iterator<Item = &'tok str> + Clone,
) -> Cow<'src, str> {
    let length: usize = parts.clone().map(str::len).sum();
    let raw = start
        .checked_add(length)
        .and_then(|end| value.get(start..end))
        .map(from_utf8);
    if let Some(Ok(text)) = raw
        && is_concat(text, parts.clone())
    {
        return Cow::Borrowed(text);
    }
    Cow::Owned(parts.collect())
}

/// Turns a run of touching tokens, or one comment or quoted string, into an item.
fn item<'src>(value: &'src [u8], run: &[Token<'_>]) -> Option<Item<'src>> {
    let first = run.first()?;
    let (kind, start) = match first.kind() {
        TokenKind::Comment => (ItemKind::Comment, first.offset().saturating_add(1)),
        TokenKind::QuotedString => (ItemKind::Word, first.offset().saturating_add(1)),
        TokenKind::Atom | TokenKind::Special(_) => (ItemKind::Word, first.offset()),
    };
    Some(Item {
        kind,
        offset: first.offset(),
        text: source_text(value, start, run.iter().map(Token::text)),
    })
}

/// Splits `tokens` at the first top-level `;`: the tokens before it and the offset of the `;`.
fn split_at_semicolon<'run, 'src>(
    tokens: &'run [Token<'src>],
) -> (&'run [Token<'src>], Option<usize>) {
    tokens
        .iter()
        .position(|token| token.kind() == TokenKind::Special(b';'))
        .and_then(|position| tokens.split_at_checked(position))
        .map_or((tokens, None), |(head, tail)| {
            (head, tail.first().map(Token::offset))
        })
}

/// The first word among `items`.
fn first_word<'src>(items: &[&Item<'src>]) -> Option<Cow<'src, str>> {
    items
        .iter()
        .find(|item| item.kind == ItemKind::Word)
        .map(|item| item.text.clone())
}

/// The first comment among `items`.
fn first_comment<'src>(items: &[&Item<'src>]) -> Option<Cow<'src, str>> {
    items
        .iter()
        .find(|item| item.kind == ItemKind::Comment)
        .map(|item| item.text.clone())
}

/// All words among `items` joined by single spaces.
fn joined_words<'src>(items: &[&Item<'src>]) -> Option<Cow<'src, str>> {
    let words: Vec<&Item<'src>> = items
        .iter()
        .copied()
        .filter(|item| item.kind == ItemKind::Word)
        .collect();
    match words.as_slice() {
        [] => None,
        [only] => Some(only.text.clone()),
        many => Some(Cow::Owned(
            many.iter()
                .map(|item| &*item.text)
                .collect::<Vec<_>>()
                .join(" "),
        )),
    }
}

/// `text` without the angle brackets around an address.
fn unbracket(text: Cow<'_, str>) -> Cow<'_, str> {
    match text {
        Cow::Borrowed(whole) => Cow::Borrowed(whole.trim_matches(['<', '>'])),
        Cow::Owned(whole) => Cow::Owned(whole.trim_matches(['<', '>']).to_owned()),
    }
}

/// `text` as an address, after an optional `IPv6:` tag; `None` when it is not one.
#[expect(
    clippy::disallowed_methods,
    reason = "text that is not an address means the clause carries no address, which is None"
)]
fn parse_ip(text: &str) -> Option<IpAddr> {
    let trimmed = text.trim();
    let untagged = trimmed
        .get(..5)
        .filter(|tag| tag.eq_ignore_ascii_case("IPv6:"))
        .and_then(|_| trimmed.get(5..))
        .unwrap_or(trimmed);
    untagged.parse().ok()
}

/// Whether `text` is a qmail `HELO name` comment, which repeats the client's claim.
fn is_helo_comment(text: &str) -> bool {
    text.split_ascii_whitespace()
        .next()
        .is_some_and(|first| first.eq_ignore_ascii_case("HELO"))
}

/// Whether the text before a `[` ends in an Exim `helo=` tag, so the literal is a claim.
fn ends_in_helo_tag(before: &str) -> bool {
    before
        .rsplit(|ch: char| ch == ',' || ch.is_ascii_whitespace())
        .next()
        .is_some_and(|last| last.eq_ignore_ascii_case("helo="))
}

/// The first `[bracketed]` address in `text` that is not tagged `helo=`.
fn bracketed_ip(text: &str) -> Option<IpAddr> {
    let mut rest = text;
    while let Some((before, after)) = rest.split_once('[') {
        let (inner, tail) = after.split_once(']')?;
        if !ends_in_helo_tag(before)
            && let Some(ip) = parse_ip(inner)
        {
            return Some(ip);
        }
        rest = tail;
    }
    None
}

/// The address the receiver recorded in a comment: the first one in `[brackets]` that is not
/// tagged `helo=`, else the whole text. A qmail `(HELO ...)` comment records none.
fn comment_ip(text: &str) -> Option<IpAddr> {
    if is_helo_comment(text) {
        return None;
    }
    bracketed_ip(text).or_else(|| parse_ip(text))
}

/// The address of a `[literal]` word; an unreadable literal is reported at the word.
fn word_ip(item: &Item<'_>, issues: &mut Vec<Issue>) -> Option<IpAddr> {
    let inner = item.text.strip_prefix('[')?.strip_suffix(']')?;
    let ip = parse_ip(inner);
    if ip.is_none() {
        issues.push(Issue::new(IssueKind::MalformedEntry, item.offset));
    }
    ip
}

/// The client address of the `from` clause: the first one a comment records, else the first
/// `[literal]` word. The words are read either way, so an unreadable literal is reported.
fn from_ip(items: &[&Item<'_>], issues: &mut Vec<Issue>) -> Option<(IpAddr, AddressSource)> {
    let claimed = items
        .iter()
        .filter(|item| item.kind == ItemKind::Word)
        .find_map(|item| word_ip(item, issues));
    let recorded = items
        .iter()
        .filter(|item| item.kind == ItemKind::Comment)
        .find_map(|item| comment_ip(&item.text));
    recorded
        .map(|ip| (ip, AddressSource::Recorded))
        .or_else(|| claimed.map(|ip| (ip, AddressSource::Claimed)))
}

/// Byte ranges of the pieces of `text` split at ASCII whitespace and commas.
fn pieces(text: &str) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut position = 0_usize;
    for piece in text.split(|ch: char| ch == ',' || ch.is_ascii_whitespace()) {
        let end = position.saturating_add(piece.len());
        if !piece.is_empty() {
            ranges.push(position..end);
        }
        position = end.saturating_add(1);
    }
    ranges
}

/// The range of the value of the first `prefix`-tagged piece, such as `version=TLS1_2`.
fn prefixed(text: &str, ranges: &[Range<usize>], prefix: &str) -> Option<Range<usize>> {
    ranges.iter().find_map(|range| {
        let rest = text.get(range.clone())?.strip_prefix(prefix)?;
        let start = range.start.saturating_add(prefix.len());
        (!rest.is_empty()).then_some(start..range.end)
    })
}

/// The range of the piece after the first piece equal to `word`, ignoring ASCII case.
fn following(text: &str, ranges: &[Range<usize>], word: &str) -> Option<Range<usize>> {
    ranges.windows(2).find_map(|pair| {
        let [head, next] = pair else {
            return None;
        };
        text.get(head.clone())?
            .eq_ignore_ascii_case(word)
            .then(|| next.clone())
    })
}

/// The part of `text` at `range`, borrowed from the source when `text` is.
fn sub<'src>(text: &Cow<'src, str>, range: Range<usize>) -> Option<Cow<'src, str>> {
    match text {
        Cow::Borrowed(whole) => (*whole).get(range).map(Cow::Borrowed),
        Cow::Owned(whole) => whole.get(range).map(|part| Cow::Owned(part.to_owned())),
    }
}

/// The TLS details in one comment; it needs a version.
fn comment_tls<'src>(text: &Cow<'src, str>) -> Option<Tls<'src>> {
    let ranges = pieces(text);
    let version =
        prefixed(text, &ranges, "version=").or_else(|| following(text, &ranges, "using"))?;
    let cipher = prefixed(text, &ranges, "cipher=").or_else(|| following(text, &ranges, "cipher"));
    Some(Tls {
        cipher: cipher.and_then(|range| sub(text, range)),
        version: sub(text, version)?,
    })
}

/// The TLS details of the first comment in the header that has them.
fn header_tls<'src>(items: &[Item<'src>]) -> Option<Tls<'src>> {
    items
        .iter()
        .filter(|item| item.kind == ItemKind::Comment)
        .find_map(|item| comment_tls(&item.text))
}

/// The date after the `;` at `semicolon` and its issues, offset into the header. A header with
/// no `;` has no date and is reported at its end.
fn read_date(value: &[u8], semicolon: Option<usize>) -> (Option<Instant>, Vec<Issue>) {
    let Some(offset) = semicolon else {
        return (
            None,
            vec![Issue::new(IssueKind::MalformedEntry, value.len())],
        );
    };
    let base = offset.saturating_add(1);
    let (date, issues) = parse_date(value.get(base..).unwrap_or(&[])).into_parts();
    let shifted = issues
        .into_iter()
        .map(|issue| Issue::new(issue.kind(), issue.offset().saturating_add(base)))
        .collect();
    (date, shifted)
}

/// Reads one header into a hop and the issues found in it. Only the first
/// [`crate::MAX_HEADER_BYTES`] bytes are read, with one issue for the cut.
fn parse_hop(index: usize, header: &[u8]) -> (Hop<'_>, Vec<Issue>) {
    let (value, cut) = bound(header);
    let (tokens, mut issues) = tokenize(value).into_parts();
    let (head, semicolon) = split_at_semicolon(&tokens);
    if let Some(offset) = semicolon {
        issues.retain(|issue| issue.offset() < offset);
    }
    let items: Vec<Item<'_>> = head
        .chunk_by(joins)
        .filter_map(|run| item(value, run))
        .collect();
    let clauses = Clauses::collect(&items);
    let ip = from_ip(&clauses.from, &mut issues);
    let (date, date_issues) = read_date(value, semicolon);
    issues.extend(date_issues);
    issues.extend(cut);
    let hop = Hop {
        by_host: first_word(&clauses.by),
        date,
        delay_seconds: None,
        from_comment: first_comment(&clauses.from),
        from_host: first_word(&clauses.from),
        header_index: index,
        id: first_word(&clauses.id),
        ip,
        protocol: joined_words(&clauses.with),
        recipient: first_word(&clauses.for_clause).map(unbracket),
        semicolon: semicolon.unwrap_or(value.len()),
        tls: header_tls(&items),
    };
    (hop, issues)
}

/// Sets each hop's delay from the hop before it, and reports a negative one at its `;`.
fn link_delays(hops: &mut [Hop<'_>]) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut previous = None;
    for hop in hops {
        hop.delay_seconds =
            previous
                .zip(hop.date)
                .and_then(|(before, after): (Instant, Instant)| {
                    after.unix_seconds().checked_sub(before.unix_seconds())
                });
        if hop.delay_seconds.is_some_and(|seconds| seconds < 0) {
            issues.push(Issue::new(IssueKind::NegativeDelay, hop.semicolon));
        }
        previous = hop.date;
    }
    issues
}

/// Whether `hop` names a sender, by host or address.
const fn has_sender(hop: &Hop<'_>) -> bool {
    hop.from_host.is_some() || hop.ip.is_some()
}

/// Whether `hop` was received by a trusted host from a sender that is not trusted. The sender
/// is judged only by the address the receiver recorded: the `from` word and a `[literal]` are
/// what the client sent in its HELO, so they cannot make it trusted, and a hop that records
/// no address counts as an untrusted sender.
fn crosses_boundary(hop: &Hop<'_>, trust: &TrustSet) -> bool {
    let received_by_us = hop
        .by_host()
        .is_some_and(|host| trust.trusts_host(host.as_bytes()));
    let sender_trusted =
        matches!(hop.ip, Some((ip, AddressSource::Recorded)) if trust.trusts_ip(ip));
    received_by_us && has_sender(hop) && !sender_trusted
}

/// Reads `headers`, the `Received` header values newest first as they appear in the message,
/// into hops in path order (oldest first).
///
/// Each hop has the fields its header carries; a part that is missing or unreadable is absent
/// and, when the text is malformed, reported as an issue at the byte offset in that header
/// (offsets are relative to the header, and [`Hop::header_index`] says which one). A header
/// with no `;` is reported at its end, and an unreadable `[address]` at the word. A hop's
/// delay is its date minus the previous hop's date; a negative delay is kept and reported as
/// [`IssueKind::NegativeDelay`] at the hop's `;`. Only the newest [`MAX_RECEIVED_HOPS`] headers
/// are read; the rest are dropped and reported once as [`IssueKind::CapExceeded`] at offset 0.
///
/// With `trust`, [`ReceivedHops::first_external`] is the newest hop whose `by` host is trusted,
/// which names a sender at all, and whose sender is not trusted. The sender is judged only by
/// the address the receiving MTA recorded in a `from` comment, matched against the trusted
/// address ranges; the `from` word and a `[literal]` word are the client's HELO, which the
/// sender chooses, so they never make it trusted. A hop that records no address (a bare
/// `from host`, an Exim `from [address] (helo=...)`, or a qmail hop with only its
/// `(HELO ...)` comment) counts as an untrusted sender and can be the boundary, so a
/// relay chain without recorded addresses fails closed.
/// Walking from the newest hop means a forged hop further back in the path cannot move it.
/// Without `trust` there is none.
#[must_use]
pub fn parse_received_hops<'src>(
    headers: &[&'src [u8]],
    trust: Option<&TrustSet>,
) -> Parsed<ReceivedHops<'src>> {
    let mut issues = Vec::new();
    if headers.len() > MAX_RECEIVED_HOPS {
        issues.push(Issue::new(
            IssueKind::CapExceeded {
                cap: Cap::ReceivedHops,
            },
            0,
        ));
    }
    let mut hops = Vec::new();
    for (index, value) in headers.iter().enumerate().take(MAX_RECEIVED_HOPS) {
        let (hop, found) = parse_hop(index, value);
        hops.push(hop);
        issues.extend(found);
    }
    hops.reverse();
    issues.extend(link_delays(&mut hops));
    let first_external =
        trust.and_then(|set| hops.iter().rposition(|hop| crosses_boundary(hop, set)));
    Parsed::new(
        ReceivedHops {
            first_external,
            hops,
        },
        issues,
    )
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{Hop, ReceivedHops, parse_received_hops};
    use crate::caps::{Cap, MAX_HEADER_BYTES, MAX_RECEIVED_HOPS};
    use crate::issue::{Issue, IssueKind, Parsed};
    use crate::trust::TrustSet;

    const POSTFIX: &str = concat!(
        "from mail.example.org (mail.example.org [192.0.2.10])\r\n",
        "\t(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)\r\n",
        "\t key-exchange X25519 server-signature RSA-PSS (2048 bits))\r\n",
        "\t(No client certificate requested)\r\n",
        "\tby mx.example.com (Postfix) with ESMTPS id 4Xabc123\r\n",
        "\tfor <alice@example.com>; 3 Nov 2026 10:00:05 +0000"
    );

    const EXCHANGE: &str = concat!(
        "from DB8PR01MB.mail.example.net (2001:db8:10:1::1) by AM9PR01MB.mail.example.net\r\n",
        " (2001:db8:20:2::2) with Microsoft SMTP Server\r\n",
        " (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.1\r\n",
        " via Frontend Transport; Tue, 3 Nov 2026 09:59:58 +0000"
    );

    const GMAIL: &str = concat!(
        "from mail-sor-f41.example.net (mail-sor-f41.example.net. [203.0.113.41])\r\n",
        " by mx.example.com with ESMTPS id 1.2.3 for <alice@example.com>\r\n",
        " (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);\r\n",
        " Tue, 03 Nov 2026 01:02:04 -0800 (PST)"
    );

    /// A forged hop the sender wrote below its real boundary hop, claiming a trusted receiver.
    const FORGED_BELOW: &str =
        "from x.example.net ([198.51.100.66]) by mx.example.com; 3 Nov 2026 10:00:00 +0000";

    const QMAIL_LOCAL: &str = "(qmail 4242 invoked by uid 1000); 3 Nov 2026 10:00:00 -0000";

    const QMAIL_REMOTE: &str = concat!(
        "from unknown (HELO mail.example.net) (203.0.113.7) by mx.example.com ",
        "with SMTP; 3 Nov 2026 10:00:03 +0000"
    );

    fn parse<'src>(headers: &[&'src str], trust: Option<&TrustSet>) -> Parsed<ReceivedHops<'src>> {
        let raw: Vec<&[u8]> = headers.iter().map(|header| header.as_bytes()).collect();
        parse_received_hops(&raw, trust)
    }

    fn trusting_our_servers() -> TrustSet {
        let mut set = TrustSet::new();
        let _chain = set
            .add_host("mx.example.com")
            .add_host("mx2.example.com")
            .add_host("mx3.example.com");
        let _range = set
            .add_ip_range("192.0.2.0/24")
            .expect("the documentation range is a valid CIDR");
        set
    }

    fn texts<'hop>(hop: &'hop Hop<'_>) -> [Option<&'hop str>; 6] {
        [
            hop.from_host(),
            hop.from_comment(),
            hop.by_host(),
            hop.protocol(),
            hop.id(),
            hop.recipient(),
        ]
    }

    fn tls_of<'hop>(hop: &'hop Hop<'_>) -> (&'hop str, Option<&'hop str>) {
        let tls = hop.tls().expect("the header has a TLS comment");
        (tls.version(), tls.cipher())
    }

    #[test]
    fn a_postfix_header_yields_every_field_with_its_tls_comment() {
        let parsed = parse(&[POSTFIX], None);
        assert_eq!(parsed.issues(), [], "a well-formed header has no issues");
        let hop = parsed.value().hops().first().expect("one header, one hop");
        assert_eq!(
            texts(hop),
            [
                Some("mail.example.org"),
                Some("mail.example.org [192.0.2.10]"),
                Some("mx.example.com"),
                Some("ESMTPS"),
                Some("4Xabc123"),
                Some("alice@example.com"),
            ],
            "from host, from comment, by host, protocol, id and recipient"
        );
        assert_eq!(
            hop.ip(),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
            "address from the bracketed text"
        );
        assert_eq!(
            tls_of(hop),
            ("TLSv1.3", Some("TLS_AES_256_GCM_SHA384")),
            "version and cipher after using"
        );
        assert_eq!(
            hop.date().map(|date| date.unix_seconds()),
            Some(1_793_700_005),
            "date after the semicolon"
        );
    }

    #[test]
    fn an_exchange_online_header_reads_the_ipv6_comment_protocol_words_and_tls() {
        let parsed = parse(&[EXCHANGE], None);
        assert_eq!(parsed.issues(), [], "a well-formed header has no issues");
        let hop = parsed.value().hops().first().expect("one header, one hop");
        assert_eq!(
            hop.ip(),
            Some(IpAddr::V6(Ipv6Addr::new(
                0x2001, 0xDB8, 0x10, 1, 0, 0, 0, 1
            ))),
            "a comment that is only an address"
        );
        assert_eq!(
            (hop.by_host(), hop.protocol(), hop.id()),
            (
                Some("AM9PR01MB.mail.example.net"),
                Some("Microsoft SMTP Server"),
                Some("15.20.1")
            ),
            "by host, protocol words and id"
        );
        assert_eq!(
            tls_of(hop),
            ("TLS1_2", Some("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")),
            "version stops at the comma"
        );
    }

    #[test]
    fn a_gmail_header_reads_the_recipient_tls_and_the_date_with_its_zone_comment() {
        let parsed = parse(&[GMAIL], None);
        assert_eq!(parsed.issues(), [], "a well-formed header has no issues");
        let hop = parsed.value().hops().first().expect("one header, one hop");
        assert_eq!(
            (hop.ip(), hop.recipient()),
            (
                Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 41))),
                Some("alice@example.com")
            ),
            "address in the reverse-lookup comment, and the for clause"
        );
        assert_eq!(
            tls_of(hop),
            ("TLS1_3", Some("TLS_AES_256_GCM_SHA384")),
            "version with a space after it"
        );
        let date = hop.date().expect("the date parses");
        assert_eq!(
            (date.unix_seconds(), date.offset_minutes()),
            (1_793_696_524, -480),
            "the date keeps its zone"
        );
    }

    #[test]
    fn qmail_headers_yield_the_helo_comment_and_a_bare_address_or_nothing() {
        let parsed = parse(&[QMAIL_REMOTE, QMAIL_LOCAL], None);
        let hops = parsed.value().hops();
        let local = hops.first().expect("the oldest header is the local one");
        assert_eq!(
            (local.from_host(), local.by_host(), local.ip()),
            (None, None, None),
            "the invoked-by comment carries no hop fields"
        );
        assert!(local.date().is_some(), "its date still parses");
        let remote = hops.get(1).expect("two headers, two hops");
        assert_eq!(remote.from_host(), Some("unknown"), "from host");
        assert_eq!(remote.from_comment(), Some("HELO mail.example.net"), "helo");
        assert_eq!(
            remote.ip(),
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
            "address from the second comment"
        );
        assert_eq!(remote.protocol(), Some("SMTP"), "protocol");
    }

    #[test]
    fn a_domain_literal_in_the_from_clause_is_the_address() {
        let header = "from [IPv6:2001:db8::25] by mx.example.com; 3 Nov 2026 10:00:00 +0000";
        let parsed = parse(&[header], None);
        let hop = parsed.value().hops().first().expect("one header, one hop");
        assert_eq!(hop.from_host(), Some("[IPv6:2001:db8::25]"), "literal kept");
        assert_eq!(
            hop.ip(),
            Some(IpAddr::V6(Ipv6Addr::new(
                0x2001, 0xDB8, 0, 0, 0, 0, 0, 0x25
            ))),
            "address from the literal"
        );
    }

    #[test]
    fn hops_come_back_oldest_first_with_each_delay_from_the_previous_hop() {
        let newest = "by c.example.com; 3 Nov 2026 10:00:30 +0000";
        let middle = "by b.example.com; 3 Nov 2026 10:00:10 +0000";
        let oldest = "by a.example.com; 3 Nov 2026 10:00:00 +0000";
        let parsed = parse(&[newest, middle, oldest], None);
        let hops = parsed.value().hops();
        let read: Vec<_> = hops
            .iter()
            .map(|hop| (hop.by_host(), hop.header_index(), hop.delay_seconds()))
            .collect();
        assert_eq!(
            read,
            vec![
                (Some("a.example.com"), 2, None),
                (Some("b.example.com"), 1, Some(10)),
                (Some("c.example.com"), 0, Some(20)),
            ],
            "path order, input positions and delays"
        );
        assert_eq!(parsed.issues(), [], "increasing dates are fine");
    }

    #[test]
    fn a_negative_delay_is_reported_at_the_semicolon_and_still_given() {
        let newest = "by b.example.com; 3 Nov 2026 10:00:00 +0000";
        let oldest = "by a.example.com; 3 Nov 2026 10:00:30 +0000";
        let parsed = parse(&[newest, oldest], None);
        let delays: Vec<_> = parsed
            .value()
            .hops()
            .iter()
            .map(Hop::delay_seconds)
            .collect();
        assert_eq!(delays, vec![None, Some(-30)], "the delay keeps its sign");
        let issues: Vec<_> = parsed
            .issues()
            .iter()
            .map(|issue| (issue.kind(), issue.offset()))
            .collect();
        assert_eq!(
            issues,
            vec![(IssueKind::NegativeDelay, 16)],
            "reported once at the newest header's semicolon"
        );
    }

    #[test]
    fn an_unreadable_date_leaves_the_delay_unset_for_that_hop_and_the_next() {
        let newest = "by c.example.com; 3 Nov 2026 10:00:30 +0000";
        let middle = "by b.example.com; not a date";
        let oldest = "by a.example.com; 3 Nov 2026 10:00:00 +0000";
        let parsed = parse(&[newest, middle, oldest], None);
        let delays: Vec<_> = parsed
            .value()
            .hops()
            .iter()
            .map(Hop::delay_seconds)
            .collect();
        assert_eq!(delays, vec![None, None, None], "no pair of readable dates");
        assert!(
            parsed
                .issues()
                .iter()
                .all(|issue| issue.offset() >= 17 && issue.kind() != IssueKind::NegativeDelay),
            "the date issues point into the middle header after its semicolon"
        );
    }

    #[test]
    fn the_newest_hop_that_crosses_from_outside_is_the_first_external_hop() {
        let inner =
            "from mx2.example.com ([192.0.2.2]) by mx3.example.com; 3 Nov 2026 10:00:03 +0000";
        let edge =
            "from mx.example.com ([192.0.2.1]) by mx2.example.com; 3 Nov 2026 10:00:02 +0000";
        let boundary =
            "from edge.example.org ([198.51.100.5]) by mx.example.com; 3 Nov 2026 10:00:01 +0000";
        let forged =
            "from liar.example.net ([198.51.100.66]) by mx.example.com; 3 Nov 2026 10:00:00 +0000";
        let set = trusting_our_servers();
        let parsed = parse(&[inner, edge, boundary, forged], Some(&set));
        assert_eq!(
            parsed.value().first_external(),
            Some(1),
            "the hop below it that claims a trusted by host does not move the boundary"
        );
        assert_eq!(
            parsed.value().hops().get(1).and_then(|hop| hop.from_host()),
            Some("edge.example.org"),
            "the index points into the oldest-first list"
        );
    }

    #[test]
    fn no_trust_set_or_no_qualifying_hop_means_no_first_external_hop() {
        let internal =
            "from mx.example.com ([192.0.2.1]) by mx2.example.com; 3 Nov 2026 10:00:02 +0000";
        let external = concat!(
            "from edge.example.org ([198.51.100.5]) by relay.example.net; ",
            "3 Nov 2026 10:00:01 +0000"
        );
        let set = trusting_our_servers();
        assert_eq!(
            parse(&[internal, external], None).value().first_external(),
            None,
            "without a trust set"
        );
        assert_eq!(
            parse(&[internal, external], Some(&set))
                .value()
                .first_external(),
            None,
            "an untrusted receiver and a trusted sender never qualify"
        );
    }

    #[test]
    fn a_hop_with_a_trusted_receiver_and_no_sender_is_not_a_boundary() {
        let local = "by mx.example.com with LMTP; 3 Nov 2026 10:00:00 +0000";
        let set = trusting_our_servers();
        assert_eq!(
            parse(&[local], Some(&set)).value().first_external(),
            None,
            "a hop that names no sender did not cross from outside"
        );
    }

    /// `first_external` of the real boundary hop `boundary` over [`FORGED_BELOW`].
    fn first_external_over_a_forged_hop(boundary: &str) -> Option<usize> {
        let set = trusting_our_servers();
        parse(&[boundary, FORGED_BELOW], Some(&set))
            .value()
            .first_external()
    }

    #[test]
    fn a_trusted_helo_name_from_an_untrusted_recorded_address_is_the_boundary() {
        let boundary = concat!(
            "from mx2.example.com (unknown [198.51.100.7]) by mx.example.com; ",
            "3 Nov 2026 10:00:01 +0000"
        );
        assert_eq!(
            first_external_over_a_forged_hop(boundary),
            Some(1),
            "the HELO name is the sender's claim, so the hop still crosses (MV-1)"
        );
    }

    #[test]
    fn a_trusted_helo_literal_from_an_untrusted_recorded_address_is_the_boundary() {
        let boundary = concat!(
            "from [192.0.2.9] (unknown [198.51.100.7]) by mx.example.com; ",
            "3 Nov 2026 10:00:01 +0000"
        );
        assert_eq!(
            first_external_over_a_forged_hop(boundary),
            Some(1),
            "the HELO literal is the sender's claim, so the hop still crosses (MV-1)"
        );
        let parsed = parse(&[boundary], None);
        assert_eq!(
            parsed.value().hops().first().and_then(Hop::ip),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))),
            "the recorded address wins over the literal"
        );
    }

    #[test]
    fn a_helo_tagged_literal_in_the_comment_is_not_the_recorded_address() {
        let exim = concat!(
            "from [198.51.100.7] (helo=[192.0.2.9]) by mx.example.com; ",
            "3 Nov 2026 10:00:01 +0000"
        );
        let qmail = concat!(
            "from unknown (HELO [192.0.2.9]) (198.51.100.7) by mx.example.com; ",
            "3 Nov 2026 10:00:01 +0000"
        );
        for boundary in [exim, qmail] {
            assert_eq!(
                parse(&[boundary], None)
                    .value()
                    .hops()
                    .first()
                    .and_then(Hop::ip),
                Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))),
                "the HELO claim is skipped in {boundary}"
            );
            assert_eq!(
                first_external_over_a_forged_hop(boundary),
                Some(1),
                "a trusted HELO address in a comment does not make the sender trusted"
            );
        }
    }

    #[test]
    fn a_hop_that_records_no_sender_address_fails_closed_as_the_boundary() {
        let bare = "from mx2.example.com by mx3.example.com; 3 Nov 2026 10:00:02 +0000";
        let edge =
            "from edge.example.org ([198.51.100.5]) by mx2.example.com; 3 Nov 2026 10:00:01 +0000";
        let set = trusting_our_servers();
        assert_eq!(
            parse(&[bare, edge], Some(&set)).value().first_external(),
            Some(1),
            "a sender named only by its HELO is untrusted, so the newer hop is the boundary"
        );
    }

    #[test]
    fn a_malformed_header_keeps_the_fields_it_has_and_reports_where_it_broke() {
        let parsed = parse(&["from mail.example.org ([192.0.2.1"], None);
        let hop = parsed.value().hops().first().expect("one header, one hop");
        assert_eq!(
            hop.from_host(),
            Some("mail.example.org"),
            "the host survives"
        );
        let issues: Vec<_> = parsed
            .issues()
            .iter()
            .map(|issue| (issue.kind(), issue.offset()))
            .collect();
        assert_eq!(
            issues,
            vec![
                (IssueKind::UnterminatedComment, 22),
                (IssueKind::MalformedEntry, 33),
            ],
            "the open comment, then the missing semicolon at the end"
        );
    }

    #[test]
    fn an_unreadable_address_literal_is_reported_at_the_word() {
        let parsed = parse(
            &["from [bogus] by mx.example.com; 3 Nov 2026 10:00:00 +0000"],
            None,
        );
        let hop = parsed.value().hops().first().expect("one header, one hop");
        assert_eq!(hop.ip(), None, "no address");
        assert_eq!(hop.by_host(), Some("mx.example.com"), "the rest is kept");
        let issues: Vec<_> = parsed
            .issues()
            .iter()
            .map(|issue| (issue.kind(), issue.offset()))
            .collect();
        assert_eq!(
            issues,
            vec![(IssueKind::MalformedEntry, 5)],
            "at the literal"
        );
    }

    #[test]
    fn headers_past_the_hop_cap_are_dropped_newest_kept_and_reported_once() {
        let header = "by mx.example.com; 3 Nov 2026 10:00:00 +0000";
        let headers = vec![header; MAX_RECEIVED_HOPS + 3];
        let parsed = parse(&headers, None);
        assert_eq!(parsed.value().hops().len(), MAX_RECEIVED_HOPS, "capped");
        assert_eq!(
            parsed.value().hops().last().map(Hop::header_index),
            Some(0),
            "the newest header is the last hop"
        );
        let caps = parsed
            .issues()
            .iter()
            .filter(|issue| {
                issue.kind()
                    == IssueKind::CapExceeded {
                        cap: Cap::ReceivedHops,
                    }
            })
            .count();
        assert_eq!(caps, 1, "one CapExceeded issue");
    }

    fn header_cap_offsets(value: &[u8]) -> Vec<usize> {
        let parsed = parse_received_hops(&[value], None);
        parsed
            .issues()
            .iter()
            .filter(|issue| {
                issue.kind()
                    == IssueKind::CapExceeded {
                        cap: Cap::HeaderBytes,
                    }
            })
            .map(Issue::offset)
            .collect()
    }

    #[test]
    fn a_header_cut_before_the_semicolon_reports_the_cap_once() {
        let mut value = b"by mx.example.com ".to_vec();
        value.resize(MAX_HEADER_BYTES + 1, b'x');
        value.extend_from_slice(b"; 3 Nov 2026 10:00:00 +0000");
        assert_eq!(header_cap_offsets(&value), vec![MAX_HEADER_BYTES]);
    }

    #[test]
    fn a_header_cut_after_the_semicolon_reports_the_cap_once() {
        let mut value = b"by mx.example.com; 3 Nov 2026 10:00:00 +0000 ".to_vec();
        value.resize(MAX_HEADER_BYTES + 1, b' ');
        assert_eq!(header_cap_offsets(&value), vec![MAX_HEADER_BYTES]);
    }
}
