//! Parser for the Microsoft antispam headers `X-Forefront-Antispam-Report` and
//! `X-Microsoft-Antispam`.
//!
//! Both headers are `KEY:VALUE` entries separated by `;`, such as `SCL:1;CIP:192.0.2.10;SRV:;`.
//! The values are not RFC 5322 structured text (an `SFS` value is a run of parenthesised rule
//! numbers, not a comment), so the value is split on raw bytes instead of going through
//! [`crate::tokenize`].

use std::borrow::Cow;
use std::net::IpAddr;
use std::str::FromStr;

use crate::caps::{Cap, MAX_ENTRIES};
use crate::issue::{Issue, IssueKind, Parsed};
use crate::tokenize::bound;

/// One `KEY:VALUE` entry, such as `SCL:1`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MsEntry<'src> {
    /// The key as written; look entries up with [`MsAntispam::get`] to ignore case.
    pub key: Cow<'src, str>,
    /// Byte offset of the key in the header value.
    pub offset: usize,
    /// The value as written between the `:` and the next `;`, with surrounding whitespace
    /// removed; empty for an entry such as `SRV:`.
    pub value: Cow<'src, str>,
}

/// A parsed Microsoft antispam header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsAntispam<'src> {
    /// The first `BCL` entry when its value is an integer from 0 to 255.
    bcl: Option<u8>,
    /// The first `CIP` entry when its value is an IP address.
    client_ip: Option<IpAddr>,
    /// Every entry in header order, repeated keys and unknown keys included.
    entries: Vec<MsEntry<'src>>,
    /// The first `SCL` entry when its value is an integer from -128 to 127.
    scl: Option<i8>,
}

impl MsAntispam<'_> {
    /// The bulk complaint level (`BCL`), when the first `BCL` entry is an integer from 0 to 255.
    #[must_use]
    pub const fn bcl(&self) -> Option<u8> {
        self.bcl
    }

    /// The spam category (`CAT`), such as `NONE` or `PHSH`.
    #[must_use]
    pub fn category(&self) -> Option<&str> {
        self.text("CAT")
    }

    /// The connecting client's address (`CIP`), when the first `CIP` entry is a valid address.
    #[must_use]
    pub const fn client_ip(&self) -> Option<IpAddr> {
        self.client_ip
    }

    /// The country the connecting client was geolocated to (`CTRY`).
    #[must_use]
    pub fn country(&self) -> Option<&str> {
        self.text("CTRY")
    }

    /// The direction of the message (`DIR`), such as `INB` or `OUT`.
    #[must_use]
    pub fn direction(&self) -> Option<&str> {
        self.text("DIR")
    }

    /// Every entry in header order, repeated keys included.
    #[must_use]
    pub fn entries(&self) -> &[MsEntry<'_>] {
        &self.entries
    }

    /// The first entry named `key`, ignoring ASCII case.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&MsEntry<'_>> {
        self.entries
            .iter()
            .find(|entry| entry.key.eq_ignore_ascii_case(key))
    }

    /// The HELO name the client gave (`H`).
    #[must_use]
    pub fn helo(&self) -> Option<&str> {
        self.text("H")
    }

    /// The IP filter verdict (`IPV`), such as `NLI` for not listed.
    #[must_use]
    pub fn ip_verdict(&self) -> Option<&str> {
        self.text("IPV")
    }

    /// The language the message was classified as (`LANG`).
    #[must_use]
    pub fn language(&self) -> Option<&str> {
        self.text("LANG")
    }

    /// The reverse DNS name of the connecting client (`PTR`).
    #[must_use]
    pub fn ptr(&self) -> Option<&str> {
        self.text("PTR")
    }

    /// The safety tip shown to the recipient (`SFTY`).
    #[must_use]
    pub fn safety(&self) -> Option<&str> {
        self.text("SFTY")
    }

    /// The spam confidence level (`SCL`), when the first `SCL` entry is an integer from -128 to
    /// 127; -1 means the message skipped spam filtering.
    #[must_use]
    pub const fn scl(&self) -> Option<i8> {
        self.scl
    }

    /// The service that handled the message (`SRV`).
    #[must_use]
    pub fn service(&self) -> Option<&str> {
        self.text("SRV")
    }

    /// The spam filter verdict (`SFV`), such as `NSPM` or `SPM`.
    #[must_use]
    pub fn spam_verdict(&self) -> Option<&str> {
        self.text("SFV")
    }

    /// The value of the first entry named `key`, empty when the entry has no value.
    fn text(&self, key: &str) -> Option<&str> {
        self.get(key).map(|entry| entry.value.as_ref())
    }
}

/// Reads `value` as the body of `X-Forefront-Antispam-Report` or `X-Microsoft-Antispam`.
///
/// Entries are split on `;` and each on its first `:`; every entry is kept in order with its
/// key and value as written, trimmed of whitespace, and the byte offset of its key. Empty
/// segments, such as the one after a trailing `;`, are skipped. A segment with no `:` or an empty
/// key is reported as [`IssueKind::MalformedEntry`] at its first byte and dropped; parsing resumes
/// after the next `;`. The first `SCL`, `BCL` and `CIP` entry whose value does not fit its type
/// (`SCL:abc`, `CIP:999.1.1.1`) stays in the list as text and is reported the same way at its
/// key. Bytes that are not UTF-8 are decoded lossily and reported as [`IssueKind::InvalidUtf8`]
/// at the entry. More than [`MAX_ENTRIES`] entries are dropped and reported once as
/// [`IssueKind::CapExceeded`]. Input past [`crate::caps::MAX_HEADER_BYTES`] is dropped and reported
/// once as [`IssueKind::CapExceeded`]. Work is linear in the length of `value`.
#[must_use]
pub fn parse_ms_antispam(value: &[u8]) -> Parsed<MsAntispam<'_>> {
    let (head, mut issues) = bound(value);
    let entries = read_entries(head, &mut issues);
    let scl = typed(&entries, "SCL", &mut issues);
    let bcl = typed(&entries, "BCL", &mut issues);
    let client_ip = typed(&entries, "CIP", &mut issues);
    issues.sort_by_key(Issue::offset);
    let parsed = MsAntispam {
        bcl,
        client_ip,
        entries,
        scl,
    };
    Parsed::new(parsed, issues)
}

/// Reads every entry of `value`; a segment that is not an entry costs one issue.
fn read_entries<'src>(value: &'src [u8], issues: &mut Vec<Issue>) -> Vec<MsEntry<'src>> {
    let mut entries = Vec::new();
    for (offset, body) in segments(value) {
        if entries.len() >= MAX_ENTRIES {
            issues.push(Issue::new(
                IssueKind::CapExceeded { cap: Cap::Entries },
                offset,
            ));
            break;
        }
        match entry(body, offset, issues) {
            Some(read) => entries.push(read),
            None => issues.push(Issue::new(IssueKind::MalformedEntry, offset)),
        }
    }
    entries
}

/// The non-blank `;` segments of `value` with whitespace trimmed, each with the byte offset
/// of its first byte.
fn segments(value: &[u8]) -> impl Iterator<Item = (usize, &[u8])> {
    let mut start = 0_usize;
    value
        .split(|byte| *byte == b';')
        .map(move |segment| {
            let begin = start;
            start = start.saturating_add(segment.len()).saturating_add(1);
            let body = segment.trim_ascii_start();
            let lead = segment.len().saturating_sub(body.len());
            (begin.saturating_add(lead), body.trim_ascii_end())
        })
        .filter(|(_, body)| !body.is_empty())
}

/// Splits `body` on its first `:`; none when there is no `:` or the key is empty.
fn entry<'src>(body: &'src [u8], offset: usize, issues: &mut Vec<Issue>) -> Option<MsEntry<'src>> {
    let colon = body.iter().position(|byte| *byte == b':')?;
    let (name, rest) = body.split_at(colon);
    let key = name.trim_ascii_end();
    let (_, value) = rest.split_first()?;
    if key.is_empty() {
        return None;
    }
    Some(MsEntry {
        key: text(key, offset, issues),
        offset,
        value: text(value.trim_ascii_start(), offset, issues),
    })
}

/// Decodes `bytes` as UTF-8, reporting at `offset` when bytes had to be replaced.
fn text<'src>(bytes: &'src [u8], offset: usize, issues: &mut Vec<Issue>) -> Cow<'src, str> {
    let decoded = String::from_utf8_lossy(bytes);
    if matches!(decoded, Cow::Owned(_)) {
        issues.push(Issue::new(IssueKind::InvalidUtf8, offset));
    }
    decoded
}

/// The first entry named `key` read as `T`; a value that does not parse is reported at the key.
fn typed<T>(entries: &[MsEntry<'_>], key: &str, issues: &mut Vec<Issue>) -> Option<T>
where
    T: FromStr,
{
    let entry = entries
        .iter()
        .find(|entry| entry.key.eq_ignore_ascii_case(key))?;
    entry.value.parse().map_or_else(
        |_| {
            issues.push(Issue::new(IssueKind::MalformedEntry, entry.offset));
            None
        },
        Some,
    )
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::parse_ms_antispam;
    use crate::caps::{Cap, MAX_ENTRIES, MAX_HEADER_BYTES};
    use crate::issue::{Issue, IssueKind};

    const FOREFRONT: &str = concat!(
        "CIP:192.0.2.10;CTRY:US;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:mail.example.com;",
        "PTR:mail.example.com;CAT:NONE;SFTY:9.25;DIR:INB;",
        "SFS:(13230040)(7416014)(5062899);ARA:1234"
    );

    const FOREFRONT_FOLDED: &str = concat!(
        "CIP:2001:db8::25;CTRY:;LANG:en;SCL:-1;SRV:;IPV:CAL;SFV:SKN;H:mx.example.net;\r\n",
        " PTR:;CAT:;SFTY:;DIR:OUT;"
    );

    const ANTISPAM: &str = concat!(
        "BCL:0;PCL:0;RULEID:(2390098)(7020095)(4652040);SRVR:AM6PR01MB1.example.com;",
        "SFS:(4636009)(1;"
    );

    fn kinds(issues: &[Issue]) -> Vec<(IssueKind, usize)> {
        issues
            .iter()
            .map(|issue| (issue.kind(), issue.offset()))
            .collect()
    }

    #[test]
    fn a_forefront_report_reads_each_typed_field() {
        let parsed = parse_ms_antispam(FOREFRONT.as_bytes());
        assert!(
            parsed.issues().is_empty(),
            "well formed: {:?}",
            parsed.issues()
        );
        let report = parsed.value();
        assert_eq!(report.scl(), Some(1), "scl");
        assert_eq!(report.bcl(), None, "no bcl entry");
        assert_eq!(
            report.client_ip(),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
            "client ip"
        );
        let text = [
            (report.country(), "US"),
            (report.language(), "en"),
            (report.service(), ""),
            (report.ip_verdict(), "NLI"),
            (report.spam_verdict(), "NSPM"),
            (report.helo(), "mail.example.com"),
            (report.ptr(), "mail.example.com"),
            (report.category(), "NONE"),
            (report.safety(), "9.25"),
            (report.direction(), "INB"),
        ];
        for (read, expected) in text {
            assert_eq!(read, Some(expected), "text field");
        }
    }

    #[test]
    fn a_forefront_report_keeps_every_entry_in_order_with_its_offset() {
        let parsed = parse_ms_antispam(FOREFRONT.as_bytes());
        let report = parsed.value();
        let keys: Vec<_> = report.entries().iter().map(|entry| &*entry.key).collect();
        assert_eq!(
            keys,
            [
                "CIP", "CTRY", "LANG", "SCL", "SRV", "IPV", "SFV", "H", "PTR", "CAT", "SFTY",
                "DIR", "SFS", "ARA"
            ],
            "every key in order"
        );
        let sfs = report.get("sfs").map(|entry| (&*entry.value, entry.offset));
        let start = FOREFRONT.find("SFS").unwrap_or(0);
        assert_eq!(
            sfs,
            Some(("(13230040)(7416014)(5062899)", start)),
            "unknown keys keep their value and offset, and lookup ignores case"
        );
    }

    #[test]
    fn a_folded_report_with_an_ipv6_client_and_scl_minus_one_reads_through_the_fold() {
        let parsed = parse_ms_antispam(FOREFRONT_FOLDED.as_bytes());
        assert!(
            parsed.issues().is_empty(),
            "well formed: {:?}",
            parsed.issues()
        );
        let report = parsed.value();
        assert_eq!(report.scl(), Some(-1), "scl -1");
        assert_eq!(
            report.client_ip(),
            Some(IpAddr::V6(Ipv6Addr::new(
                0x2001, 0xDB8, 0, 0, 0, 0, 0, 0x25
            ))),
            "ipv6 client"
        );
        assert_eq!(report.ptr(), Some(""), "folded entry is trimmed and empty");
        assert_eq!(report.direction(), Some("OUT"), "entry after the fold");
        assert_eq!(report.entries().len(), 12, "trailing ; adds no entry");
    }

    #[test]
    fn an_x_microsoft_antispam_header_reads_bcl_and_keeps_pcl_and_rule_ids() {
        let parsed = parse_ms_antispam(ANTISPAM.as_bytes());
        assert!(
            parsed.issues().is_empty(),
            "well formed: {:?}",
            parsed.issues()
        );
        let report = parsed.value();
        assert_eq!(report.bcl(), Some(0), "bcl");
        assert_eq!(report.scl(), None, "no scl entry");
        let pcl = report.get("PCL").map(|entry| (&*entry.value, entry.offset));
        assert_eq!(pcl, Some(("0", 6)), "pcl kept verbatim at its offset");
        let rules = report.get("RULEID").map(|entry| &*entry.value);
        assert_eq!(rules, Some("(2390098)(7020095)(4652040)"), "rule ids");
        assert_eq!(report.entries().len(), 5, "every entry kept");
    }

    #[test]
    fn empty_values_give_some_empty_text_and_no_issue() {
        let parsed = parse_ms_antispam(b"SRV:;PTR:;");
        assert!(
            parsed.issues().is_empty(),
            "no issue: {:?}",
            parsed.issues()
        );
        let report = parsed.value();
        assert_eq!(report.service(), Some(""), "srv");
        assert_eq!(report.ptr(), Some(""), "ptr");
        assert_eq!(report.helo(), None, "absent key");
        assert_eq!(report.entries().len(), 2, "two entries");
    }

    #[test]
    fn a_typed_value_that_does_not_fit_stays_text_with_an_issue_and_no_typed_value() {
        let input = "SCL:abc;BCL:300;CIP:999.1.1.1;H:mx.example.com";
        let parsed = parse_ms_antispam(input.as_bytes());
        let report = parsed.value();
        assert_eq!(report.scl(), None, "scl");
        assert_eq!(report.bcl(), None, "bcl out of range");
        assert_eq!(report.client_ip(), None, "cip");
        assert_eq!(
            report.helo(),
            Some("mx.example.com"),
            "later entries survive"
        );
        assert_eq!(
            kinds(parsed.issues()),
            vec![
                (IssueKind::MalformedEntry, 0),
                (IssueKind::MalformedEntry, 8),
                (IssueKind::MalformedEntry, 16),
            ],
            "one issue at each key"
        );
    }

    #[test]
    fn a_typed_value_that_does_not_fit_is_kept_verbatim_in_the_entry_list() {
        let parsed = parse_ms_antispam(b"SCL:abc;CIP:999.1.1.1");
        let entries = parsed.value().entries();
        let values: Vec<_> = entries.iter().map(|entry| &*entry.value).collect();
        assert_eq!(values, ["abc", "999.1.1.1"], "text kept");
    }

    #[test]
    fn only_the_first_entry_of_a_key_is_typed() {
        let parsed = parse_ms_antispam(b"SCL:x;SCL:5");
        assert_eq!(parsed.value().scl(), None, "first entry decides");
        assert_eq!(parsed.value().entries().len(), 2, "both kept");
    }

    #[test]
    fn an_entry_without_a_colon_is_reported_and_parsing_resumes_after_the_next_semicolon() {
        let parsed = parse_ms_antispam(b"SCL:1; junk ;BCL:2;:x;DIR:INB");
        let report = parsed.value();
        assert_eq!(report.scl(), Some(1), "before");
        assert_eq!(report.bcl(), Some(2), "after the bad segment");
        assert_eq!(report.direction(), Some("INB"), "after an empty key");
        assert_eq!(report.entries().len(), 3, "bad segments are dropped");
        assert_eq!(
            kinds(parsed.issues()),
            vec![
                (IssueKind::MalformedEntry, 7),
                (IssueKind::MalformedEntry, 19)
            ],
            "issues at the segments"
        );
    }

    #[test]
    fn invalid_utf8_is_decoded_lossily_and_reported_at_the_entry() {
        let parsed = parse_ms_antispam(b"H:mx\xff.example.com");
        assert_eq!(
            parsed.value().helo(),
            Some("mx\u{fffd}.example.com"),
            "lossy"
        );
        assert_eq!(
            kinds(parsed.issues()),
            vec![(IssueKind::InvalidUtf8, 0)],
            "issue"
        );
    }

    #[test]
    fn a_value_one_byte_over_the_header_cap_is_cut_and_reported_at_the_cap() {
        let mut input = b"SCL:1;K:".to_vec();
        input.resize(MAX_HEADER_BYTES + 1, b'a');
        let parsed = parse_ms_antispam(&input);
        assert_eq!(parsed.value().entries().len(), 2, "entries before the cut");
        assert_eq!(parsed.value().scl(), Some(1), "typed fields survive");
        assert_eq!(
            kinds(parsed.issues()),
            vec![(
                IssueKind::CapExceeded {
                    cap: Cap::HeaderBytes
                },
                MAX_HEADER_BYTES
            )],
            "one issue at the cap"
        );
    }

    #[test]
    fn entries_beyond_the_cap_are_dropped_and_reported_once() {
        let input = b"K:v;".repeat(MAX_ENTRIES.saturating_add(5));
        let parsed = parse_ms_antispam(&input);
        assert_eq!(
            parsed.value().entries().len(),
            MAX_ENTRIES,
            "kept up to the cap"
        );
        assert_eq!(
            kinds(parsed.issues()),
            vec![(
                IssueKind::CapExceeded { cap: Cap::Entries },
                MAX_ENTRIES.saturating_mul(4)
            )],
            "one issue at the first dropped entry"
        );
    }

    #[test]
    fn empty_input_gives_no_entries_and_no_issue() {
        let parsed = parse_ms_antispam(b"");
        assert!(parsed.value().entries().is_empty(), "no entries");
        assert!(parsed.issues().is_empty(), "no issues");
    }
}
