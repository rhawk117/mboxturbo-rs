//! Property tests for the plan's invariant I2: no parser panics, every issue offset lies
//! within the input, and every cap overflow is reported as exactly one `CapExceeded` issue.

#[cfg(test)]
mod properties {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use mboxturbo_headers::{
        ArcHeader, Cap, Issue, IssueKind, MAX_COMMENT_DEPTH, MAX_ENCODED_WORDS, MAX_ENTRIES,
        MAX_HEADER_BYTES, MAX_RECEIVED_HOPS, TrustSet, decode_encoded_words, parse_arc_sets,
        parse_authentication_results, parse_date, parse_dkim_signature, parse_received_hops,
        parse_received_spf, parse_tag_list, tokenize,
    };
    use proptest::prelude::*;

    fn config() -> ProptestConfig {
        ProptestConfig::with_cases(64)
    }

    fn arbitrary_bytes() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 0..4096)
    }

    fn from_alphabet(alphabet: &'static [u8]) -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(prop::sample::select(alphabet), 0..4096)
    }

    fn from_alphabet_up_to(alphabet: &'static [u8], max: usize) -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(prop::sample::select(alphabet), 0..max)
    }

    fn tokenize_adversarial() -> impl Strategy<Value = Vec<u8>> {
        from_alphabet(b"(()\\\"<>[]@:;,. \r\nab=")
    }

    fn encoded_word_adversarial() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(
            prop::sample::select(vec![
                &b"=?"[..],
                b"?=",
                b"?",
                b"utf-8",
                b"iso-8859-1",
                b"B",
                b"Q",
                b"=",
                b"=C3",
                b"a",
                b"_",
                b" ",
            ]),
            0..512,
        )
        .prop_map(|parts| parts.concat())
    }

    fn date_adversarial() -> impl Strategy<Value = Vec<u8>> {
        from_alphabet(b"0123456789+-:, ()MonTueWdhFriSatunJFbarpyglOctNvDeZGMTESTCDP")
    }

    fn tag_list_adversarial() -> impl Strategy<Value = Vec<u8>> {
        from_alphabet(b";;==  \r\nabdhbvsc:/+")
    }

    fn auth_results_adversarial() -> impl Strategy<Value = Vec<u8>> {
        from_alphabet(b";;==..  \"()/abdkimspfnoe1")
    }

    fn received_spf_adversarial() -> impl Strategy<Value = Vec<u8>> {
        from_alphabet(b";;==  \r\n\"()passfilnetrk-ip.:1a0")
    }

    fn received_adversarial() -> impl Strategy<Value = Vec<Vec<u8>>> {
        prop::collection::vec(
            from_alphabet_up_to(b";;()[]<>:. \r\nfrombyidwthaelo0123456789:@-", 96),
            0..24,
        )
    }

    fn arc_adversarial() -> impl Strategy<Value = Vec<(u8, Vec<u8>)>> {
        prop::collection::vec(
            (
                0_u8..3,
                prop::collection::vec(
                    prop::sample::select(b"i=;;0123456789 \r\nabcdv=pasnoe.".as_slice()),
                    0..96,
                ),
            ),
            0..64,
        )
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

    proptest! {
        #![proptest_config(config())]

        #[test]
        fn tokenize_survives_arbitrary_bytes(input in arbitrary_bytes()) {
            assert_offsets_within(tokenize(&input).issues(), input.len())?;
        }

        #[test]
        fn tokenize_survives_adversarial_delimiters(input in tokenize_adversarial()) {
            assert_offsets_within(tokenize(&input).issues(), input.len())?;
        }

        #[test]
        fn decode_encoded_words_survives_arbitrary_bytes(input in arbitrary_bytes()) {
            assert_offsets_within(decode_encoded_words(&input).issues(), input.len())?;
        }

        #[test]
        fn decode_encoded_words_survives_adversarial_runs(input in encoded_word_adversarial()) {
            assert_offsets_within(decode_encoded_words(&input).issues(), input.len())?;
        }

        #[test]
        fn parse_date_survives_arbitrary_bytes(input in arbitrary_bytes()) {
            assert_offsets_within(parse_date(&input).issues(), input.len())?;
        }

        #[test]
        fn parse_date_survives_adversarial_digits_signs_and_zones(input in date_adversarial()) {
            assert_offsets_within(parse_date(&input).issues(), input.len())?;
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

        #[test]
        fn parse_authentication_results_survives_arbitrary_bytes(
            input in arbitrary_bytes(),
            trusted in any::<bool>(),
        ) {
            let set = trusting("mx.example.com");
            let parsed = parse_authentication_results(&input, trusted.then_some(&set));
            assert_offsets_within(parsed.issues(), input.len())?;
        }

        #[test]
        fn parse_authentication_results_survives_adversarial_separators(
            input in auth_results_adversarial(),
            trusted in any::<bool>(),
        ) {
            let set = trusting("a");
            let parsed = parse_authentication_results(&input, trusted.then_some(&set));
            assert_offsets_within(parsed.issues(), input.len())?;
        }

        #[test]
        fn parse_received_spf_survives_arbitrary_bytes(input in arbitrary_bytes()) {
            assert_offsets_within(parse_received_spf(&input).issues(), input.len())?;
        }

        #[test]
        fn parse_received_spf_survives_adversarial_separators(input in received_spf_adversarial()) {
            assert_offsets_within(parse_received_spf(&input).issues(), input.len())?;
        }

        #[test]
        fn parse_received_hops_survives_arbitrary_headers(
            raw in prop::collection::vec(arbitrary_bytes(), 0..8),
            trusted in any::<bool>(),
        ) {
            let set = trusting("mx.example.com");
            let headers: Vec<&[u8]> = raw.iter().map(Vec::as_slice).collect();
            let parsed = parse_received_hops(&headers, trusted.then_some(&set));
            let longest = raw.iter().map(Vec::len).max().unwrap_or(0);
            assert_offsets_within(parsed.issues(), longest)?;
        }

        #[test]
        fn parse_received_hops_survives_adversarial_separators(
            raw in received_adversarial(),
            trusted in any::<bool>(),
        ) {
            let set = trusting("mx.example.com");
            let headers: Vec<&[u8]> = raw.iter().map(Vec::as_slice).collect();
            let parsed = parse_received_hops(&headers, trusted.then_some(&set));
            let longest = raw.iter().map(Vec::len).max().unwrap_or(0);
            assert_offsets_within(parsed.issues(), longest)?;
        }

        #[test]
        fn tag_list_and_dkim_survive_arbitrary_bytes(input in arbitrary_bytes()) {
            assert_offsets_within(parse_tag_list(&input).issues(), input.len())?;
            assert_offsets_within(parse_dkim_signature(&input).issues(), input.len())?;
        }

        #[test]
        fn tag_list_and_dkim_survive_adversarial_separators(input in tag_list_adversarial()) {
            assert_offsets_within(parse_tag_list(&input).issues(), input.len())?;
            assert_offsets_within(parse_dkim_signature(&input).issues(), input.len())?;
        }
    }

    proptest! {
        #![proptest_config(config())]

        #[test]
        fn parse_arc_sets_survives_arbitrary_header_lists(raw in arc_adversarial()) {
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
        fn parse_arc_sets_survives_arbitrary_bytes(
            kind in 0_u8..3,
            value in arbitrary_bytes(),
        ) {
            let raw = vec![(kind, value)];
            let headers = arc_headers(&raw);
            let len = raw.first().map_or(0, |(_, bytes)| bytes.len());
            assert_offsets_within(parse_arc_sets(&headers, None).issues(), len)?;
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(8))]

        #[test]
        fn more_arc_headers_than_the_cap_are_reported_once(
            extra in 1_usize..64,
            instance in 1_u8..=50,
        ) {
            let value = format!("i={instance}; cv=none").into_bytes();
            let headers = vec![ArcHeader::Seal(&value); MAX_ENTRIES.saturating_add(extra)];
            let issues = parse_arc_sets(&headers, None).issues().to_vec();
            prop_assert_eq!(cap_issues(&issues, Cap::Entries), 1, "one Entries issue");
        }

        #[test]
        fn nesting_past_the_comment_depth_cap_is_reported_once(
            extra in 1_usize..64,
            filler in arbitrary_bytes(),
        ) {
            let mut input = vec![b'('; MAX_COMMENT_DEPTH.saturating_add(extra)];
            input.extend(filler.iter().filter(|byte| !matches!(byte, b'(' | b')' | b'\\' | b'"')));
            let issues = tokenize(&input).issues().to_vec();
            prop_assert_eq!(cap_issues(&issues, Cap::CommentDepth), 1, "one CommentDepth issue");
            assert_offsets_within(&issues, input.len())?;
        }

        #[test]
        fn more_encoded_words_than_the_cap_are_reported_once(extra in 1_usize..64) {
            let input = b"=?utf-8?q?a?= ".repeat(MAX_ENCODED_WORDS.saturating_add(extra));
            let issues = decode_encoded_words(&input).issues().to_vec();
            prop_assert_eq!(cap_issues(&issues, Cap::EncodedWords), 1, "one EncodedWords issue");
            assert_offsets_within(&issues, input.len())?;
        }

        #[test]
        fn more_auth_entries_than_the_cap_are_reported_once(extra in 1_usize..64) {
            let mut input = b"mx.example.com".to_vec();
            input.extend(b"; spf=pass".repeat(MAX_ENTRIES.saturating_add(extra)));
            let issues = parse_authentication_results(&input, None).issues().to_vec();
            prop_assert_eq!(cap_issues(&issues, Cap::Entries), 1, "one Entries issue");
            assert_offsets_within(&issues, input.len())?;
        }

        #[test]
        fn more_received_spf_pairs_than_the_cap_are_reported_once(extra in 1_usize..64) {
            let mut input = b"pass".to_vec();
            input.extend(b"; k=v".repeat(MAX_ENTRIES.saturating_add(extra)));
            let issues = parse_received_spf(&input).issues().to_vec();
            prop_assert_eq!(cap_issues(&issues, Cap::Entries), 1, "one Entries issue");
            assert_offsets_within(&issues, input.len())?;
        }

        #[test]
        fn more_received_headers_than_the_hop_cap_are_reported_once(extra in 1_usize..64) {
            let header: &[u8] = b"by mx.example.com; 3 Nov 2026 10:00:00 +0000";
            let headers = vec![header; MAX_RECEIVED_HOPS.saturating_add(extra)];
            let parsed = parse_received_hops(&headers, None);
            let capped = cap_issues(parsed.issues(), Cap::ReceivedHops);
            prop_assert_eq!(capped, 1, "one ReceivedHops issue");
            prop_assert_eq!(parsed.value().hops().len(), MAX_RECEIVED_HOPS, "the rest is dropped");
        }

        #[test]
        fn a_header_longer_than_the_byte_cap_is_reported_once(
            extra in 1_usize..64,
            byte in b'a'..=b'z',
        ) {
            let input = vec![byte; MAX_HEADER_BYTES.saturating_add(extra)];
            let tokens = tokenize(&input).issues().to_vec();
            prop_assert_eq!(cap_issues(&tokens, Cap::HeaderBytes), 1, "tokenize flags the cap");
            assert_offsets_within(&tokens, input.len())?;
            let auth = parse_authentication_results(&input, None).issues().to_vec();
            prop_assert_eq!(cap_issues(&auth, Cap::HeaderBytes), 1, "auth results flag the cap");
        }
    }
}
