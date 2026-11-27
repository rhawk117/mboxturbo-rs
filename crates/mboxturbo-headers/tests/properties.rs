//! Property tests for the plan's invariant I2: no parser panics, every issue offset lies
//! within the input, and every cap overflow is reported as exactly one `CapExceeded` issue.

#[cfg(test)]
mod properties {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use mboxturbo_headers::{
        ArcHeader, Cap, Issue, IssueKind, MAX_COMMENT_DEPTH, MAX_ENCODED_WORDS, MAX_ENTRIES,
        MAX_HEADER_BYTES, MAX_RECEIVED_HOPS, TrustSet, decode_encoded_words, parse_arc_sets,
        parse_authentication_results, parse_date, parse_dkim_signature, parse_ms_antispam,
        parse_received_hops, parse_received_spf, parse_tag_list, tokenize,
    };
    use proptest::prelude::*;

    const BOGUS_CHARSETS: [&[u8]; 6] = [
        b"",
        b"x-bogus",
        b"utf-8",
        b"\xff\xfe",
        b"iso-8859-1",
        b"*en",
    ];

    const BOGUS_ENCODINGS: [&[u8]; 5] = [b"", b"Z", b"B", b"Q", b"bb"];

    const BOGUS_PAYLOADS: [&[u8]; 7] = [b"", b"=", b"=C", b"=ZZ", b"!!!!", b"YQ==", b"a_b"];

    const CAP_CASES: [CapCase; 22] = [
        (
            "tokenize",
            Cap::HeaderBytes,
            MAX_HEADER_BYTES,
            filler,
            tokenize_issues,
        ),
        (
            "decode_encoded_words",
            Cap::HeaderBytes,
            MAX_HEADER_BYTES,
            filler,
            encoded_word_issues,
        ),
        (
            "parse_date",
            Cap::HeaderBytes,
            MAX_HEADER_BYTES,
            filler,
            date_issues,
        ),
        (
            "parse_authentication_results",
            Cap::HeaderBytes,
            MAX_HEADER_BYTES,
            filler,
            auth_results_issues,
        ),
        (
            "parse_authentication_results trusted",
            Cap::HeaderBytes,
            MAX_HEADER_BYTES,
            filler,
            trusted_auth_results_issues,
        ),
        (
            "parse_tag_list",
            Cap::HeaderBytes,
            MAX_HEADER_BYTES,
            filler,
            tag_list_issues,
        ),
        (
            "parse_dkim_signature",
            Cap::HeaderBytes,
            MAX_HEADER_BYTES,
            filler,
            dkim_issues,
        ),
        (
            "parse_received_spf",
            Cap::HeaderBytes,
            MAX_HEADER_BYTES,
            filler,
            received_spf_issues,
        ),
        (
            "parse_ms_antispam",
            Cap::HeaderBytes,
            MAX_HEADER_BYTES,
            filler,
            ms_antispam_issues,
        ),
        (
            "parse_received_hops",
            Cap::HeaderBytes,
            MAX_HEADER_BYTES,
            filler,
            received_hops_issues,
        ),
        (
            "parse_arc_sets",
            Cap::HeaderBytes,
            MAX_HEADER_BYTES,
            filler,
            arc_issues,
        ),
        (
            "tokenize",
            Cap::CommentDepth,
            MAX_COMMENT_DEPTH,
            open_comments,
            tokenize_issues,
        ),
        (
            "parse_date",
            Cap::CommentDepth,
            MAX_COMMENT_DEPTH,
            open_comments,
            date_issues,
        ),
        (
            "parse_received_spf",
            Cap::CommentDepth,
            MAX_COMMENT_DEPTH,
            open_comments,
            received_spf_issues,
        ),
        (
            "parse_received_hops",
            Cap::CommentDepth,
            MAX_COMMENT_DEPTH,
            open_comments,
            received_hops_issues,
        ),
        (
            "parse_authentication_results",
            Cap::Entries,
            MAX_ENTRIES,
            auth_entries,
            auth_results_issues,
        ),
        (
            "parse_authentication_results trusted",
            Cap::Entries,
            MAX_ENTRIES,
            auth_entries,
            trusted_auth_results_issues,
        ),
        (
            "parse_received_spf",
            Cap::Entries,
            MAX_ENTRIES,
            spf_pairs,
            received_spf_issues,
        ),
        (
            "parse_ms_antispam",
            Cap::Entries,
            MAX_ENTRIES,
            antispam_entries,
            ms_antispam_issues,
        ),
        (
            "parse_tag_list",
            Cap::Entries,
            MAX_ENTRIES,
            numbered_tags,
            tag_list_issues,
        ),
        (
            "parse_dkim_signature",
            Cap::Entries,
            MAX_ENTRIES,
            numbered_tags,
            dkim_issues,
        ),
        (
            "decode_encoded_words",
            Cap::EncodedWords,
            MAX_ENCODED_WORDS,
            encoded_words,
            encoded_word_issues,
        ),
    ];

    const FAMILY_ALPHABETS: [&[u8]; 8] = [
        b"(()\\\"<>[]@:;,. \r\nab=",
        b"0123456789+-:, ()MonTueWdhFriSatunJFbarpyglOctNvDeZGMTESTCDP",
        b";;==  \r\nabdhbvsc:/+",
        b";;==..  \"()/abdkimspfnoe1",
        b";;==  \r\n\"()passfilnetrk-ip.:1a0",
        b";;::  \r\n()SCLBCIPSRV.-0123456789abcdef\xff",
        b";;()[]<>:. \r\nfrombyidwthaelo0123456789:@-",
        b"i=;;0123456789 \r\nabcdv=pasnoe.",
    ];

    const FLOOD_UNITS: [&[u8]; 6] = [b"; a=b", b"; spf=pass", b"K:v;", b"a=b;", b",a@b", b" (c)"];

    type Build = fn(usize) -> Vec<u8>;

    /// Parser name, the cap it applies, the bound in the cap's unit, an input builder for a count
    /// of that unit, and the parser run.
    type CapCase = (&'static str, Cap, usize, Build, Run);

    type Run = fn(&[u8]) -> Vec<Issue>;

    fn config() -> ProptestConfig {
        ProptestConfig::with_cases(48)
    }

    fn arbitrary_bytes() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 0..4096)
    }

    fn delimiter_runs() -> impl Strategy<Value = Vec<u8>> {
        prop::sample::select(FAMILY_ALPHABETS.to_vec()).prop_flat_map(|alphabet| {
            prop::collection::vec(prop::sample::select(alphabet), 0..4096)
        })
    }

    fn deep_nesting() -> impl Strategy<Value = Vec<u8>> {
        (
            2_000_usize..6_000,
            prop::sample::select(b"(<[\"\\".as_slice()),
            any::<bool>(),
        )
            .prop_map(|(depth, open, close)| {
                let mut input = vec![open; depth];
                if close {
                    input.extend(vec![b')'; depth]);
                }
                input
            })
    }

    fn entry_flood() -> impl Strategy<Value = Vec<u8>> {
        (prop::sample::select(FLOOD_UNITS.to_vec()), 0_usize..200)
            .prop_map(|(unit, extra)| unit.repeat(MAX_ENTRIES.saturating_add(extra)))
    }

    fn invalid_utf8_runs() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(
            prop_oneof![3 => 0x80_u8..=0xff, 1 => b'a'..=b'z', 1 => Just(b' ')],
            0..4096,
        )
    }

    fn bogus_encoded_words() -> impl Strategy<Value = Vec<u8>> {
        let word = (
            prop::sample::select(BOGUS_CHARSETS.to_vec()),
            prop::sample::select(BOGUS_ENCODINGS.to_vec()),
            prop::sample::select(BOGUS_PAYLOADS.to_vec()),
        )
            .prop_map(|(charset, encoding, payload)| {
                [&b"=?"[..], charset, b"?", encoding, b"?", payload, b"?="].concat()
            });
        prop::collection::vec(word, 0..64).prop_map(|words| words.join(&b' '))
    }

    fn hostile_input() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            arbitrary_bytes(),
            delimiter_runs(),
            deep_nesting(),
            entry_flood(),
            invalid_utf8_runs(),
            bogus_encoded_words(),
        ]
    }

    fn hostile_headers() -> impl Strategy<Value = Vec<Vec<u8>>> {
        prop::collection::vec(hostile_input(), 0..6)
    }

    fn arc_headers(raw: &[(u8, Vec<u8>)]) -> Vec<ArcHeader<'_>> {
        raw.iter()
            .map(|(kind, value)| match kind {
                0 => ArcHeader::Seal(value),
                1 => ArcHeader::MessageSignature(value),
                _ => ArcHeader::AuthenticationResults(value),
            })
            .collect()
    }

    fn ip_text() -> impl Strategy<Value = String> {
        prop::collection::vec(
            prop::sample::select(b"0123456789abcdefABCDEF:./%-+ x".as_slice()),
            0..64,
        )
        .prop_map(|bytes| bytes.into_iter().map(char::from).collect())
    }

    fn assert_offsets_within(issues: &[Issue], len: usize) -> Result<(), TestCaseError> {
        for issue in issues {
            prop_assert!(
                issue.offset() <= len,
                "issue {:?} points past the {len}-byte input",
                issue
            );
        }
        Ok(())
    }

    fn assert_range_error_within(set: &mut TrustSet, range: &str) -> Result<(), TestCaseError> {
        if let Err(error) = set.add_ip_range(range) {
            prop_assert!(
                error.offset() <= range.len(),
                "range error offset {} points past the {}-byte text",
                error.offset(),
                range.len()
            );
        }
        Ok(())
    }

    fn trusting(id: &str) -> TrustSet {
        let mut set = TrustSet::new();
        let _chain = set.add_authserv_id(id);
        set
    }

    fn cap_issues(issues: &[Issue], cap: Cap) -> usize {
        issues
            .iter()
            .filter(|issue| issue.kind() == IssueKind::CapExceeded { cap })
            .count()
    }

    fn tokenize_issues(input: &[u8]) -> Vec<Issue> {
        tokenize(input).issues().to_vec()
    }

    fn encoded_word_issues(input: &[u8]) -> Vec<Issue> {
        decode_encoded_words(input).issues().to_vec()
    }

    fn date_issues(input: &[u8]) -> Vec<Issue> {
        parse_date(input).issues().to_vec()
    }

    fn auth_results_issues(input: &[u8]) -> Vec<Issue> {
        parse_authentication_results(input, None).issues().to_vec()
    }

    fn trusted_auth_results_issues(input: &[u8]) -> Vec<Issue> {
        let set = trusting("mx.example.com");
        parse_authentication_results(input, Some(&set))
            .issues()
            .to_vec()
    }

    fn tag_list_issues(input: &[u8]) -> Vec<Issue> {
        parse_tag_list(input).issues().to_vec()
    }

    fn dkim_issues(input: &[u8]) -> Vec<Issue> {
        parse_dkim_signature(input).issues().to_vec()
    }

    fn received_spf_issues(input: &[u8]) -> Vec<Issue> {
        parse_received_spf(input).issues().to_vec()
    }

    fn ms_antispam_issues(input: &[u8]) -> Vec<Issue> {
        parse_ms_antispam(input).issues().to_vec()
    }

    fn received_hops_issues(input: &[u8]) -> Vec<Issue> {
        parse_received_hops(&[input], None).issues().to_vec()
    }

    fn arc_issues(input: &[u8]) -> Vec<Issue> {
        parse_arc_sets(&[ArcHeader::Seal(input)], None)
            .issues()
            .to_vec()
    }

    fn filler(len: usize) -> Vec<u8> {
        vec![b'a'; len]
    }

    fn open_comments(depth: usize) -> Vec<u8> {
        vec![b'('; depth]
    }

    fn auth_entries(count: usize) -> Vec<u8> {
        [&b"mx.example.com"[..], &b"; spf=pass".repeat(count)].concat()
    }

    fn spf_pairs(count: usize) -> Vec<u8> {
        [&b"pass"[..], &b"; k=v".repeat(count)].concat()
    }

    fn antispam_entries(count: usize) -> Vec<u8> {
        b"K:v;".repeat(count)
    }

    fn numbered_tags(count: usize) -> Vec<u8> {
        (0..count)
            .flat_map(|index| format!("t{index}=v;").into_bytes())
            .collect()
    }

    fn encoded_words(count: usize) -> Vec<u8> {
        b"=?utf-8?q?a?= ".repeat(count)
    }

    fn assert_cap_boundary(cap: Cap, extra: usize) -> Result<(), TestCaseError> {
        for &(parser, case_cap, bound, build, run) in CAP_CASES.iter().filter(|case| case.1 == cap)
        {
            let over = run(&build(bound.saturating_add(extra)));
            prop_assert_eq!(
                cap_issues(&over, case_cap),
                1,
                "{} reports {:?} exactly once just over the bound",
                parser,
                case_cap
            );
            let at = run(&build(bound));
            prop_assert_eq!(
                cap_issues(&at, case_cap),
                0,
                "{} reports no {:?} at the bound",
                parser,
                case_cap
            );
        }
        Ok(())
    }

    fn arc_seals(count: usize) -> Vec<Issue> {
        let value = b"i=1; cv=none".to_vec();
        let headers = vec![ArcHeader::Seal(&value); count];
        parse_arc_sets(&headers, None).issues().to_vec()
    }

    fn hop_report(count: usize) -> (usize, usize) {
        let header: &[u8] = b"by mx.example.com; 3 Nov 2026 10:00:00 +0000";
        let parsed = parse_received_hops(&vec![header; count], None);
        (
            cap_issues(parsed.issues(), Cap::ReceivedHops),
            parsed.value().hops().len(),
        )
    }

    proptest! {
        #![proptest_config(config())]

        #[test]
        fn tokenize_survives_hostile_input(input in hostile_input()) {
            assert_offsets_within(tokenize(&input).issues(), input.len())?;
        }

        #[test]
        fn decode_encoded_words_survives_hostile_input(input in hostile_input()) {
            assert_offsets_within(decode_encoded_words(&input).issues(), input.len())?;
        }

        #[test]
        fn parse_date_survives_hostile_input(input in hostile_input()) {
            assert_offsets_within(parse_date(&input).issues(), input.len())?;
        }

        #[test]
        fn parse_authentication_results_without_trust_survives_hostile_input(
            input in hostile_input(),
        ) {
            let parsed = parse_authentication_results(&input, None);
            assert_offsets_within(parsed.issues(), input.len())?;
        }

        #[test]
        fn parse_authentication_results_with_trust_survives_hostile_input(
            input in hostile_input(),
            id in prop::sample::select(vec!["mx.example.com", "a", ""]),
        ) {
            let set = trusting(id);
            let parsed = parse_authentication_results(&input, Some(&set));
            assert_offsets_within(parsed.issues(), input.len())?;
        }

        #[test]
        fn parse_tag_list_survives_hostile_input(input in hostile_input()) {
            assert_offsets_within(parse_tag_list(&input).issues(), input.len())?;
        }

        #[test]
        fn parse_dkim_signature_survives_hostile_input(input in hostile_input()) {
            assert_offsets_within(parse_dkim_signature(&input).issues(), input.len())?;
        }

        #[test]
        fn parse_received_spf_survives_hostile_input(input in hostile_input()) {
            assert_offsets_within(parse_received_spf(&input).issues(), input.len())?;
        }

        #[test]
        fn parse_ms_antispam_survives_hostile_input(input in hostile_input()) {
            assert_offsets_within(parse_ms_antispam(&input).issues(), input.len())?;
        }

        #[test]
        fn parse_received_hops_survives_hostile_input(
            raw in hostile_headers(),
            trusted in any::<bool>(),
        ) {
            let set = trusting("mx.example.com");
            let headers: Vec<&[u8]> = raw.iter().map(Vec::as_slice).collect();
            let parsed = parse_received_hops(&headers, trusted.then_some(&set));
            let longest = raw.iter().map(Vec::len).max().unwrap_or(0);
            assert_offsets_within(parsed.issues(), longest)?;
        }

        #[test]
        fn parse_arc_sets_survives_hostile_input(
            raw in prop::collection::vec((0_u8..3, hostile_input()), 0..6),
        ) {
            let headers = arc_headers(&raw);
            let parsed = parse_arc_sets(&headers, None);
            let longest = raw.iter().map(|(_, value)| value.len()).max().unwrap_or(0);
            assert_offsets_within(parsed.issues(), longest)?;
            prop_assert!(
                parsed.value().iter().all(|set| (1..=50).contains(&set.instance())),
                "every set carries an instance from 1 to 50"
            );
        }

        #[test]
        fn trust_set_survives_arbitrary_strings(
            text in any::<String>(),
            bytes in arbitrary_bytes(),
        ) {
            let mut set = TrustSet::new();
            let _chain = set.add_host(&text).add_authserv_id(&text);
            assert_range_error_within(&mut set, &text)?;
            let _by_bytes = set.trusts_host(&bytes);
            let _id = set.trusts_authserv_id(&bytes);
            let _by_text = set.trusts_host(text.as_bytes());
        }

        #[test]
        fn trust_set_survives_adversarial_ip_ranges(
            range in ip_text(),
            v4 in any::<u32>(),
            v6 in any::<u128>(),
        ) {
            let mut set = TrustSet::new();
            assert_range_error_within(&mut set, &range)?;
            let _v4 = set.trusts_ip(IpAddr::V4(Ipv4Addr::from(v4)));
            let _v6 = set.trusts_ip(IpAddr::V6(Ipv6Addr::from(v6)));
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4))]

        #[test]
        fn header_bytes_cap_is_reported_once_by_every_parser_past_the_bound(extra in 1_usize..64) {
            assert_cap_boundary(Cap::HeaderBytes, extra)?;
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(8))]

        #[test]
        fn comment_depth_cap_is_reported_once_by_every_parser_past_the_bound(extra in 1_usize..64) {
            assert_cap_boundary(Cap::CommentDepth, extra)?;
        }

        #[test]
        fn entries_cap_is_reported_once_by_every_parser_past_the_bound(extra in 1_usize..64) {
            assert_cap_boundary(Cap::Entries, extra)?;
        }

        #[test]
        fn encoded_words_cap_is_reported_once_by_every_parser_past_the_bound(extra in 1_usize..64) {
            assert_cap_boundary(Cap::EncodedWords, extra)?;
        }

        #[test]
        fn arc_headers_past_the_entries_cap_are_reported_once(extra in 1_usize..64) {
            let over = arc_seals(MAX_ENTRIES.saturating_add(extra));
            prop_assert_eq!(cap_issues(&over, Cap::Entries), 1, "one Entries issue past the bound");
            let at = arc_seals(MAX_ENTRIES);
            prop_assert_eq!(cap_issues(&at, Cap::Entries), 0, "no Entries issue at the bound");
        }

        #[test]
        fn received_headers_past_the_hop_cap_are_reported_once_and_dropped(extra in 1_usize..64) {
            let (capped, kept) = hop_report(MAX_RECEIVED_HOPS.saturating_add(extra));
            prop_assert_eq!(capped, 1, "one ReceivedHops issue past the bound");
            prop_assert_eq!(kept, MAX_RECEIVED_HOPS, "the rest is dropped");
            let (at_capped, at_kept) = hop_report(MAX_RECEIVED_HOPS);
            prop_assert_eq!(at_capped, 0, "no ReceivedHops issue at the bound");
            prop_assert_eq!(at_kept, MAX_RECEIVED_HOPS, "every hop at the bound is kept");
        }
    }
}
