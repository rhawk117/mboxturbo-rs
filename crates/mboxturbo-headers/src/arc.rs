//! Grouping of the ARC headers of one message into sets (RFC 8617).
//!
//! Each hop adds an `ARC-Seal`, an `ARC-Message-Signature` and an `ARC-Authentication-Results`
//! header that share an `i=` instance number. The first two are DKIM tag lists; the third is
//! `i=N;` followed by an `Authentication-Results` body.

use std::borrow::Cow;
use std::collections::BTreeMap;

use crate::auth_results::{AuthenticationResults, parse_authentication_results};
use crate::caps::{Cap, MAX_ENTRIES};
use crate::dkim::{TagList, parse_tag_list};
use crate::issue::{ArcPart, ArcProblem, Issue, IssueKind, Parsed};
use crate::tokenize::bound;
use crate::trust::TrustSet;

/// Highest instance number RFC 8617 allows.
const MAX_INSTANCE: u8 = 50;

/// The value of one ARC header, tagged with the header it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArcHeader<'src> {
    /// The value of an `ARC-Authentication-Results` header.
    AuthenticationResults(&'src [u8]),
    /// The value of an `ARC-Message-Signature` header.
    MessageSignature(&'src [u8]),
    /// The value of an `ARC-Seal` header.
    Seal(&'src [u8]),
}

/// The chain validation status a seal records in its `cv=` tag.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChainValidation<'src> {
    /// `cv=fail`.
    Fail,
    /// `cv=none`, as the first seal of a chain carries.
    None,
    /// Any other text, kept as written.
    Other(Cow<'src, str>),
    /// `cv=pass`.
    Pass,
}

impl<'src> ChainValidation<'src> {
    /// Reads a `cv=` value, matching `none`, `pass` and `fail` without regard to case.
    const fn from_text(text: &'src str) -> Self {
        if text.eq_ignore_ascii_case("none") {
            Self::None
        } else if text.eq_ignore_ascii_case("pass") {
            Self::Pass
        } else if text.eq_ignore_ascii_case("fail") {
            Self::Fail
        } else {
            Self::Other(Cow::Borrowed(text))
        }
    }

    /// The `cv=` text: lowercase for a status with a variant of its own, verbatim for any other.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Fail => "fail",
            Self::None => "none",
            Self::Other(text) => text,
            Self::Pass => "pass",
        }
    }
}

/// The ARC headers that share one instance number; any of the three may be absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArcSet<'src> {
    /// The `ARC-Authentication-Results` of this instance.
    authentication_results: Option<AuthenticationResults<'src>>,
    /// The instance number, 1 to 50.
    instance: u8,
    /// The `ARC-Message-Signature` tags of this instance.
    message_signature: Option<TagList<'src>>,
    /// The `ARC-Seal` tags of this instance.
    seal: Option<TagList<'src>>,
}

impl<'src> ArcSet<'src> {
    /// The body of this hop's `ARC-Authentication-Results` after its `i=N;`; `None` when the
    /// set has no such header.
    #[must_use]
    pub const fn authentication_results(&self) -> Option<&AuthenticationResults<'src>> {
        self.authentication_results.as_ref()
    }

    /// The seal's `cv=` value; `None` when the seal is absent or has no `cv` tag. The match
    /// ignores case; any text other than `none`, `pass` and `fail` is
    /// [`ChainValidation::Other`].
    #[must_use]
    pub fn chain_validation(&self) -> Option<ChainValidation<'_>> {
        let tag = self.seal.as_ref()?.get("cv")?;
        Some(ChainValidation::from_text(tag.value()))
    }

    /// An empty set for `instance`.
    const fn empty(instance: u8) -> Self {
        Self {
            authentication_results: None,
            instance,
            message_signature: None,
            seal: None,
        }
    }

    /// The instance number, 1 to 50.
    #[must_use]
    pub const fn instance(&self) -> u8 {
        self.instance
    }

    /// The tags of this hop's `ARC-Message-Signature`, if present.
    #[must_use]
    pub const fn message_signature(&self) -> Option<&TagList<'src>> {
        self.message_signature.as_ref()
    }

    /// The tags of this hop's `ARC-Seal`, if present.
    #[must_use]
    pub const fn seal(&self) -> Option<&TagList<'src>> {
        self.seal.as_ref()
    }
}

/// One header read into the slot it belongs to.
enum Part<'src> {
    /// An `ARC-Authentication-Results` body.
    Results(AuthenticationResults<'src>),
    /// An `ARC-Seal` tag list.
    Seal(TagList<'src>),
    /// An `ARC-Message-Signature` tag list.
    Signature(TagList<'src>),
}

/// Builds an [`IssueKind::ArcInstance`] issue.
const fn arc_issue(instance: u8, problem: ArcProblem, offset: usize) -> Issue {
    Issue::new(IssueKind::ArcInstance { instance, problem }, offset)
}

/// Accepts `number` as an instance when it is 1 to 50, otherwise reports it at `offset`.
fn check_instance(number: u32, offset: usize, issues: &mut Vec<Issue>) -> Option<u8> {
    let clamped = u8::try_from(number).map_or(u8::MAX, u8::from);
    if (1..=MAX_INSTANCE).contains(&clamped) {
        return Some(clamped);
    }
    issues.push(arc_issue(clamped, ArcProblem::InstanceOutOfRange, offset));
    None
}

/// Reads the `i=` tag of a seal or message signature.
fn read_tag_instance(list: &TagList<'_>, len: usize, issues: &mut Vec<Issue>) -> Option<u8> {
    let Some(tag) = list.get("i") else {
        issues.push(arc_issue(0, ArcProblem::MissingInstance, len));
        return None;
    };
    let Ok(number) = tag.value().parse::<u32>() else {
        issues.push(Issue::new(IssueKind::MalformedEntry, tag.offset()));
        return None;
    };
    check_instance(number, tag.offset(), issues)
}

/// Reads a seal or message signature into its tag list and instance.
fn read_tags<'src>(value: &'src [u8], issues: &mut Vec<Issue>) -> Option<(u8, TagList<'src>)> {
    let (list, found) = parse_tag_list(value).into_parts();
    issues.extend(found);
    let instance = read_tag_instance(&list, value.len(), issues)?;
    Some((instance, list))
}

/// Offset of the first byte at or after `at` that is not ASCII whitespace.
fn skip_space(value: &[u8], at: usize) -> usize {
    // An offset past the end has no bytes to skip, so the empty rest is the right answer.
    let rest = value.get(at..).unwrap_or(&[]);
    at.saturating_add(
        rest.iter()
            .take_while(|byte| byte.is_ascii_whitespace())
            .count(),
    )
}

/// The offset after `want` when it is the byte at `at`.
fn byte_at(value: &[u8], at: usize, want: u8) -> Option<usize> {
    (value.get(at) == Some(&want)).then_some(at.saturating_add(1))
}

/// Reads the decimal number starting at `at` and returns it with the offset after it.
fn read_number(value: &[u8], at: usize) -> Option<(u32, usize)> {
    let digits: Vec<u8> = value
        .get(at..)?
        .iter()
        .copied()
        .take_while(u8::is_ascii_digit)
        .collect();
    if digits.is_empty() {
        return None;
    }
    let number = digits.iter().try_fold(0_u32, |sum, digit| {
        sum.checked_mul(10)?
            .checked_add(u32::from(digit.saturating_sub(b'0')))
    })?;
    Some((number, at.saturating_add(digits.len())))
}

/// Splits `i=N;` from an `ARC-Authentication-Results` value, giving the number, where it
/// starts and the offset of the text after the `;`.
fn split_instance(value: &[u8]) -> Option<(u32, usize, usize)> {
    let tag = skip_space(value, 0);
    let equals = skip_space(value, byte_at(value, tag, b'i')?);
    let start = skip_space(value, byte_at(value, equals, b'=')?);
    let (number, end) = read_number(value, start)?;
    let body = byte_at(value, skip_space(value, end), b';')?;
    Some((number, start, body))
}

/// Reads an `ARC-Authentication-Results` value into its body and instance.
fn read_results<'src>(
    value: &'src [u8],
    trust: Option<&TrustSet>,
    issues: &mut Vec<Issue>,
) -> Option<(u8, AuthenticationResults<'src>)> {
    let (head, cut) = bound(value);
    issues.extend(cut);
    let Some((number, number_at, body_at)) = split_instance(head) else {
        issues.push(Issue::new(IssueKind::MalformedEntry, 0));
        return None;
    };
    let instance = check_instance(number, number_at, issues)?;
    let body = head.get(body_at..)?;
    let (results, found) = parse_authentication_results(body, trust).into_parts();
    issues.extend(
        found
            .into_iter()
            .map(|issue| Issue::new(issue.kind(), issue.offset().saturating_add(body_at))),
    );
    Some((instance, results))
}

/// Reads one header into its instance and slot.
fn read_header<'src>(
    header: ArcHeader<'src>,
    trust: Option<&TrustSet>,
    issues: &mut Vec<Issue>,
) -> Option<(u8, Part<'src>)> {
    match header {
        ArcHeader::Seal(value) => {
            read_tags(value, issues).map(|(instance, list)| (instance, Part::Seal(list)))
        },
        ArcHeader::MessageSignature(value) => {
            read_tags(value, issues).map(|(instance, list)| (instance, Part::Signature(list)))
        },
        ArcHeader::AuthenticationResults(value) => read_results(value, trust, issues)
            .map(|(instance, body)| (instance, Part::Results(body))),
    }
}

/// Stores `value` in `slot`, or pushes `duplicate` and keeps the first.
fn fill<T>(slot: &mut Option<T>, value: T, duplicate: Issue, issues: &mut Vec<Issue>) {
    if slot.is_some() {
        issues.push(duplicate);
    } else {
        *slot = Some(value);
    }
}

/// Puts `part` into the set for `instance`, creating the set when it is new.
fn place<'src>(
    sets: &mut BTreeMap<u8, ArcSet<'src>>,
    instance: u8,
    part: Part<'src>,
    issues: &mut Vec<Issue>,
) {
    let set = sets
        .entry(instance)
        .or_insert_with(|| ArcSet::empty(instance));
    let duplicate = |kind| arc_issue(instance, ArcProblem::DuplicatePart { part: kind }, 0);
    match part {
        Part::Results(body) => fill(
            &mut set.authentication_results,
            body,
            duplicate(ArcPart::AuthenticationResults),
            issues,
        ),
        Part::Seal(list) => fill(&mut set.seal, list, duplicate(ArcPart::Seal), issues),
        Part::Signature(list) => fill(
            &mut set.message_signature,
            list,
            duplicate(ArcPart::MessageSignature),
            issues,
        ),
    }
}

/// Reports each header kind `set` lacks.
fn report_missing(set: &ArcSet<'_>, issues: &mut Vec<Issue>) {
    let parts = [
        (set.seal.is_none(), ArcPart::Seal),
        (set.message_signature.is_none(), ArcPart::MessageSignature),
        (
            set.authentication_results.is_none(),
            ArcPart::AuthenticationResults,
        ),
    ];
    for (absent, part) in parts {
        if absent {
            let problem = ArcProblem::MissingPart { part };
            issues.push(arc_issue(set.instance, problem, 0));
        }
    }
}

/// Reports every instance from 1 to the highest present that has no set, and every set that
/// is incomplete.
fn audit(sets: &BTreeMap<u8, ArcSet<'_>>, issues: &mut Vec<Issue>) {
    let highest = sets.last_key_value().map_or(0, |(instance, _)| *instance);
    for instance in 1..=highest {
        match sets.get(&instance) {
            Some(set) => report_missing(set, issues),
            None => issues.push(arc_issue(instance, ArcProblem::Gap, 0)),
        }
    }
}

/// Groups ARC headers into sets by instance number.
///
/// `headers` are the values in message order. Each set holds the seal and message-signature
/// tag lists and the `Authentication-Results` body of one instance, ordered by instance. A
/// header with no usable `i=` (missing, not a number, 0 or above 50) is dropped with an issue
/// at its `i` tag (the number for an `ARC-Authentication-Results`), at the end of the value when it
/// is missing, or at offset 0 for an
/// `ARC-Authentication-Results` without a leading `i=N;`. A repeated header kind in one
/// instance keeps the first and reports [`ArcProblem::DuplicatePart`] at offset 0 of the
/// repeat. An absent header kind and a missing instance below the highest present are reported
/// at offset 0 as [`ArcProblem::MissingPart`] and [`ArcProblem::Gap`]. Issues of the tag-list
/// and `Authentication-Results` parsers are included with offsets relative to their header.
/// Headers beyond [`MAX_ENTRIES`] are dropped and reported once as [`IssueKind::CapExceeded`]
/// at offset 0. Work is linear in the total length of `headers`.
#[must_use]
pub fn parse_arc_sets<'src>(
    headers: &[ArcHeader<'src>],
    trust: Option<&TrustSet>,
) -> Parsed<Vec<ArcSet<'src>>> {
    let mut issues = Vec::new();
    if headers.len() > MAX_ENTRIES {
        issues.push(Issue::new(IssueKind::CapExceeded { cap: Cap::Entries }, 0));
    }
    let mut sets = BTreeMap::new();
    for header in headers.iter().copied().take(MAX_ENTRIES) {
        if let Some((instance, part)) = read_header(header, trust, &mut issues) {
            place(&mut sets, instance, part, &mut issues);
        }
    }
    audit(&sets, &mut issues);
    Parsed::new(sets.into_values().collect(), issues)
}

#[cfg(test)]
mod tests {
    use super::{ArcHeader, ArcSet, ChainValidation, parse_arc_sets};
    use crate::caps::{Cap, MAX_ENTRIES, MAX_HEADER_BYTES};
    use crate::dkim::Tag;
    use crate::issue::{ArcPart, ArcProblem, Issue, IssueKind};

    fn seal(instance: u8, cv: &str) -> Vec<u8> {
        format!("i={instance}; a=rsa-sha256; d=hop{instance}.example; s=arc; cv={cv}; b=AAAA")
            .into_bytes()
    }

    fn signature(instance: u8) -> Vec<u8> {
        format!("i={instance}; a=rsa-sha256; d=hop{instance}.example; s=arc; bh=AAAA; b=BBBB")
            .into_bytes()
    }

    fn results(instance: u8) -> Vec<u8> {
        format!("i={instance}; mx{instance}.example; spf=pass smtp.mailfrom=a@example.org")
            .into_bytes()
    }

    fn arc_issue(instance: u8, problem: ArcProblem, offset: usize) -> Issue {
        Issue::new(IssueKind::ArcInstance { instance, problem }, offset)
    }

    fn chain() -> Vec<(u8, Vec<u8>)> {
        let mut raw = Vec::new();
        for (instance, cv) in [(3, "pass"), (1, "none"), (2, "pass")] {
            raw.push((0, seal(instance, cv)));
            raw.push((1, signature(instance)));
            raw.push((2, results(instance)));
        }
        raw
    }

    fn headers(raw: &[(u8, Vec<u8>)]) -> Vec<ArcHeader<'_>> {
        raw.iter()
            .map(|(kind, value)| match kind {
                0 => ArcHeader::Seal(value),
                1 => ArcHeader::MessageSignature(value),
                _ => ArcHeader::AuthenticationResults(value),
            })
            .collect()
    }

    #[test]
    fn a_three_hop_chain_groups_into_sets_ordered_by_instance_with_each_cv() {
        let raw = chain();
        let parsed = parse_arc_sets(&headers(&raw), None);
        assert!(parsed.issues().is_empty(), "a complete chain has no issues");
        let sets = parsed.value();
        let instances: Vec<u8> = sets.iter().map(ArcSet::instance).collect();
        assert_eq!(instances, [1, 2, 3], "sets are ordered by instance");
        let cvs: Vec<_> = sets.iter().map(ArcSet::chain_validation).collect();
        assert_eq!(
            cvs,
            [
                Some(ChainValidation::None),
                Some(ChainValidation::Pass),
                Some(ChainValidation::Pass)
            ],
            "each seal's cv is read",
        );
    }

    #[test]
    fn each_set_holds_the_three_parts_of_its_own_instance() {
        let raw = chain();
        let parsed = parse_arc_sets(&headers(&raw), None);
        let second = parsed.value().get(1).expect("the second set exists");
        let domain = second.seal().and_then(|tags| tags.get("d"));
        assert_eq!(
            domain.map(Tag::value),
            Some("hop2.example"),
            "the seal tags belong to their own instance",
        );
        let hash = second.message_signature().and_then(|tags| tags.get("bh"));
        assert_eq!(
            hash.map(Tag::value),
            Some("AAAA"),
            "the signature is attached"
        );
        let body = second
            .authentication_results()
            .expect("the second set carries its authentication results");
        assert_eq!(body.authserv_id(), "mx2.example", "the AAR body is parsed");
    }

    #[test]
    fn an_unknown_cv_keeps_its_raw_text_and_known_ones_ignore_case() {
        let (odd, loud) = (seal(1, "maybe"), seal(2, "FAIL"));
        let headers = [ArcHeader::Seal(&odd), ArcHeader::Seal(&loud)];
        let parsed = parse_arc_sets(&headers, None);
        let cvs: Vec<_> = parsed
            .value()
            .iter()
            .map(ArcSet::chain_validation)
            .collect();
        assert_eq!(
            cvs,
            [
                Some(ChainValidation::Other("maybe".into())),
                Some(ChainValidation::Fail)
            ],
            "unknown text is kept and FAIL is Fail",
        );
    }

    #[test]
    fn a_missing_part_and_a_gap_are_reported_and_the_sets_are_kept() {
        let (first_seal, third_seal, third_sig) = (seal(1, "none"), seal(3, "pass"), signature(3));
        let headers = [
            ArcHeader::Seal(&first_seal),
            ArcHeader::Seal(&third_seal),
            ArcHeader::MessageSignature(&third_sig),
        ];
        let parsed = parse_arc_sets(&headers, None);
        assert_eq!(parsed.value().len(), 2, "both recovered sets are returned");
        let part = |part| ArcProblem::MissingPart { part };
        assert_eq!(
            parsed.issues(),
            [
                arc_issue(1, part(ArcPart::MessageSignature), 0),
                arc_issue(1, part(ArcPart::AuthenticationResults), 0),
                arc_issue(2, ArcProblem::Gap, 0),
                arc_issue(3, part(ArcPart::AuthenticationResults), 0),
            ],
            "missing parts and the gap name their instance",
        );
    }

    #[test]
    fn a_duplicated_header_keeps_the_first_and_names_the_instance() {
        let (first, second) = (seal(1, "none"), seal(1, "fail"));
        let headers = [ArcHeader::Seal(&first), ArcHeader::Seal(&second)];
        let parsed = parse_arc_sets(&headers, None);
        assert_eq!(
            parsed.value().first().and_then(ArcSet::chain_validation),
            Some(ChainValidation::None),
            "the first seal wins",
        );
        let duplicate = ArcProblem::DuplicatePart {
            part: ArcPart::Seal,
        };
        assert_eq!(
            parsed.issues().first(),
            Some(&arc_issue(1, duplicate, 0)),
            "the duplicate is reported",
        );
    }

    fn out_of_range(instance: u8) -> Issue {
        arc_issue(instance, ArcProblem::InstanceOutOfRange, 0)
    }

    #[test]
    fn instances_outside_one_to_fifty_are_dropped_with_an_issue_at_the_tag() {
        let (zero, high, kept) = (seal(0, "none"), seal(51, "none"), seal(50, "pass"));
        let headers = [
            ArcHeader::Seal(&zero),
            ArcHeader::Seal(&high),
            ArcHeader::Seal(&kept),
        ];
        let parsed = parse_arc_sets(&headers, None);
        assert_eq!(
            parsed.issues().get(..2),
            Some([out_of_range(0), out_of_range(51)].as_slice()),
            "0 and 51 are rejected at the tag",
        );
        assert_eq!(parsed.value().len(), 1, "only instance 50 is kept");
    }

    #[test]
    fn an_instance_too_large_for_u32_is_a_malformed_entry_at_the_tag() {
        let huge = b"i=99999999999".to_vec();
        let parsed = parse_arc_sets(&[ArcHeader::MessageSignature(&huge)], None);
        assert!(
            parsed
                .issues()
                .contains(&Issue::new(IssueKind::MalformedEntry, 0)),
            "an unreadable number is a malformed entry",
        );
        assert!(parsed.value().is_empty(), "the header is dropped");
    }

    #[test]
    fn a_header_without_an_instance_is_dropped_and_reported() {
        let seal_text = b"a=rsa-sha256; cv=none".to_vec();
        let results_text = b"mx.example; spf=pass".to_vec();
        let headers = [
            ArcHeader::Seal(&seal_text),
            ArcHeader::AuthenticationResults(&results_text),
        ];
        let parsed = parse_arc_sets(&headers, None);
        assert!(parsed.value().is_empty(), "nothing can be placed");
        assert_eq!(
            parsed.issues(),
            [
                arc_issue(0, ArcProblem::MissingInstance, seal_text.len()),
                Issue::new(IssueKind::MalformedEntry, 0),
            ],
            "the seal reports at the end, the results at the start",
        );
    }

    #[test]
    fn results_issues_are_offset_from_the_start_of_the_arc_header() {
        let text = b"i=1; mx.example; spf".to_vec();
        let headers = [ArcHeader::AuthenticationResults(&text)];
        let parsed = parse_arc_sets(&headers, None);
        let offsets: Vec<usize> = parsed
            .issues()
            .iter()
            .filter(|issue| issue.kind() == IssueKind::MalformedEntry)
            .map(Issue::offset)
            .collect();
        assert_eq!(
            offsets,
            [17],
            "the malformed result is located in the whole header"
        );
    }

    #[test]
    fn an_authentication_results_value_one_byte_over_the_header_cap_is_cut_and_reported_at_the_cap()
    {
        let mut value = b"i=1;".to_vec();
        value.resize(MAX_HEADER_BYTES + 1, b' ');
        let raw = [(2, value)];
        let parsed = parse_arc_sets(&headers(&raw), None);
        let cap = IssueKind::CapExceeded {
            cap: Cap::HeaderBytes,
        };
        let capped: Vec<usize> = parsed
            .issues()
            .iter()
            .filter(|issue| issue.kind() == cap)
            .map(Issue::offset)
            .collect();
        assert_eq!(capped, [MAX_HEADER_BYTES], "one issue at the cap");
        assert_eq!(
            parsed.value().first().map(ArcSet::instance),
            Some(1),
            "the instance before the cut is read"
        );
    }

    #[test]
    fn headers_past_the_entry_cap_are_dropped_and_reported_once() {
        let text = seal(1, "none");
        let headers = vec![ArcHeader::Seal(&text); MAX_ENTRIES.saturating_add(5)];
        let parsed = parse_arc_sets(&headers, None);
        let cap = IssueKind::CapExceeded { cap: Cap::Entries };
        let count = parsed
            .issues()
            .iter()
            .filter(|issue| issue.kind() == cap)
            .count();
        assert_eq!(count, 1, "one CapExceeded issue");
        let duplicates = parsed
            .issues()
            .iter()
            .filter(|issue| {
                matches!(
                    issue.kind(),
                    IssueKind::ArcInstance {
                        problem: ArcProblem::DuplicatePart { .. },
                        ..
                    }
                )
            })
            .count();
        assert_eq!(
            duplicates,
            MAX_ENTRIES.saturating_sub(1),
            "only the first MAX_ENTRIES are read"
        );
    }
}
