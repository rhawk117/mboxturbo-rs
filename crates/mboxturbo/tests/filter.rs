//! A predicate filter keeps the right messages in order, reads only the headers it names, and
//! the predicate round-trips through its documented JSON form.

#[cfg(test)]
mod filter {
    use std::fs;
    use std::sync::Arc;

    use arrow_array::cast::AsArray as _;
    use mboxturbo::{
        CancelToken, Column, DateBounds, Filter, Mailbox, MboxTurboError, Narrowing, Pipeline,
        Predicate, PredicateFault, Selection, TrustSet, VerdictMethod,
    };
    use proptest::prelude::*;
    use tempfile::TempDir;

    /// Seven messages exercising case, folding, repeats and a header-looking body line.
    const MESSAGES: &str = "From a@example.com Mon Jan  1 00:00:00 2024\n\
Subject: Invoice 2024 due\n\
X-Spam-Flag: YES\n\
List-Id: <a.example.org>\n\
\n\
body\n\
\n\
From b@example.com Mon Jan  1 00:00:00 2024\n\
Subject: Re: lunch\n\
X-Spam-Flag: NO\n\
\n\
body\n\
\n\
From c@example.com Mon Jan  1 00:00:00 2024\n\
Subject: Quarterly\n\
\x20invoice\n\
\tsummary\n\
\n\
body\n\
\n\
From d@example.com Mon Jan  1 00:00:00 2024\n\
Subject: tags\n\
X-Tag: alpha\n\
X-Tag: beta\n\
\n\
body\n\
\n\
From e@example.com Mon Jan  1 00:00:00 2024\n\
Subject: plain\n\
\n\
X-Spam-Flag: YES\n\
\n\
From f@example.com Mon Jan  1 00:00:00 2024\n\
SUBJECT: shouting\n\
x-spam-flag: YES\n\
\n\
body\n\
\n\
From g@example.com Mon Jan  1 00:00:00 2024\n\
Subject: empty list id\n\
List-Id:\n\
\n\
body\n";

    /// Three messages: a forged `Authentication-Results` above a real one, an id-less header above
    /// the first external hop, and the same header below it.
    const VERDICTS: &str = "From a@example.com Mon Jan  1 00:00:00 2024\n\
Authentication-Results: evil.example; dmarc=pass header.from=example.org\n\
Authentication-Results: mx.example.org; dmarc=fail header.from=example.org;\n\
\tspf=pass smtp.mailfrom=example.org; dkim=softfail header.d=example.org\n\
Subject: forged above real\n\
\n\
body\n\
\n\
From b@example.com Tue Jan  2 00:00:00 2024\n\
Authentication-Results: spf=pass smtp.mailfrom=example.org; dkim=pass header.d=example.org;\n\
\tdmarc=pass action=none header.from=example.org; compauth=pass reason=100\n\
Received: from sender.example.net (sender.example.net [203.0.113.5])\n\
\tby mx.example.org with ESMTPS id 1; Mon, 2 Nov 2026 10:00:00 +0000\n\
Subject: id-less above the first external hop\n\
\n\
body\n\
\n\
From c@example.com Wed Jan  3 00:00:00 2024\n\
Received: from sender.example.net (sender.example.net [203.0.113.5])\n\
\tby mx.example.org with ESMTPS id 2; Mon, 2 Nov 2026 10:00:00 +0000\n\
Authentication-Results: spf=pass smtp.mailfrom=example.org; dkim=pass header.d=example.org;\n\
\tdmarc=pass action=none header.from=example.org; compauth=pass reason=100\n\
Subject: id-less below the first external hop\n\
\n\
body\n";

    /// A mailbox on disk, kept alive with its directory.
    struct Fixture {
        _directory: TempDir,
        mailbox: Arc<Mailbox>,
    }

    impl Fixture {
        fn with(contents: &str) -> Self {
            let directory = tempfile::tempdir().expect("temporary directory is created");
            let path = directory.path().join("inbox.mbox");
            fs::write(&path, contents).expect("fixture mbox is written");
            let mailbox = Arc::new(Mailbox::open(&path).expect("fixture mbox opens"));
            Self {
                _directory: directory,
                mailbox,
            }
        }
    }

    fn header(name: &str) -> String {
        name.to_owned()
    }

    fn exists(name: &str) -> Predicate {
        Predicate::Exists {
            header: header(name),
        }
    }

    fn equals(name: &str, value: &str) -> Predicate {
        Predicate::Equals {
            header: header(name),
            value: value.to_owned(),
        }
    }

    fn contains(name: &str, value: &str) -> Predicate {
        Predicate::Contains {
            header: header(name),
            value: value.to_owned(),
        }
    }

    fn starts_with(name: &str, value: &str) -> Predicate {
        Predicate::StartsWith {
            header: header(name),
            value: value.to_owned(),
        }
    }

    fn verdict(method: VerdictMethod, word: &str) -> Predicate {
        Predicate::Verdict {
            method,
            equals: word.to_owned(),
        }
    }

    fn negated(predicate: Predicate) -> Predicate {
        Predicate::Not {
            arg: Box::new(predicate),
        }
    }

    fn trust_mx_relay() -> TrustSet {
        TrustSet::new()
            .add_authserv_id("mx.example.org")
            .add_host("mx.example.org")
            .clone()
    }

    fn positions(fixture: &Fixture, predicate: &Predicate) -> Vec<usize> {
        let filter = Filter::new(predicate).expect("the predicate is valid");
        selected(&fixture.mailbox, &filter)
    }

    fn selected(mailbox: &Mailbox, filter: &Filter) -> Vec<usize> {
        let narrowed = Narrowing::new()
            .filter(filter)
            .select(mailbox, None)
            .expect("the filter pass reads the mailbox");
        match narrowed.selection {
            Selection::Positions(found) => found,
            Selection::All => (0..mailbox.len()).collect(),
            other @ (Selection::Ranges(_) | _) => panic!("narrowing yielded {other:?}"),
        }
    }

    fn verdict_positions(predicate: &Predicate, trust: Option<TrustSet>) -> Vec<usize> {
        let fixture = Fixture::with(VERDICTS);
        let plain = Filter::new(predicate).expect("the predicate is valid");
        let filter = match trust {
            Some(set) => plain.with_trust(set),
            None => plain,
        };
        selected(&fixture.mailbox, &filter)
    }

    #[test]
    fn exists_matches_a_header_in_any_letter_case_and_ignores_the_body() {
        let fixture = Fixture::with(MESSAGES);
        assert_eq!(
            positions(&fixture, &exists("LIST-id")),
            [0, 6],
            "an empty value still exists"
        );
        assert_eq!(
            positions(&fixture, &exists("x-spam-flag")),
            [0, 1, 5],
            "the body line of message 4 is not a header, and SUBJECT or x-spam-flag spellings count"
        );
    }

    #[test]
    fn equals_compares_bytes_exactly() {
        let fixture = Fixture::with(MESSAGES);
        assert_eq!(
            positions(&fixture, &equals("X-Spam-Flag", "YES")),
            [0, 5],
            "the leading space after the colon is trimmed and the name matches in any case"
        );
        assert_eq!(
            positions(&fixture, &equals("X-Spam-Flag", "yes")),
            Vec::<usize>::new(),
            "letter case in the value matters"
        );
        assert_eq!(
            positions(&fixture, &equals("Subject", "Invoice 2024")),
            Vec::<usize>::new(),
            "equality is whole-value"
        );
    }

    #[test]
    fn contains_and_starts_with_test_the_value() {
        let fixture = Fixture::with(MESSAGES);
        assert_eq!(
            positions(&fixture, &contains("subject", "Invoice")),
            [0],
            "message 2 spells it in lowercase"
        );
        assert_eq!(
            positions(&fixture, &starts_with("subject", "Re: ")),
            [1],
            "only message 1 starts with the prefix"
        );
        assert_eq!(
            positions(&fixture, &starts_with("subject", "voice")),
            Vec::<usize>::new(),
            "a prefix is not a substring"
        );
    }

    #[test]
    fn regex_matches_anywhere_in_a_value() {
        let fixture = Fixture::with(MESSAGES);
        let predicate = Predicate::regex("subject", r"\d{4} d").expect("the pattern compiles");
        assert_eq!(
            positions(&fixture, &predicate),
            [0],
            "the unanchored pattern matches inside the subject"
        );
    }

    #[test]
    fn a_folded_header_is_compared_unfolded() {
        let fixture = Fixture::with(MESSAGES);
        assert_eq!(
            positions(&fixture, &equals("subject", "Quarterly invoice\tsummary")),
            [2],
            "the fold line breaks are removed and the indentation is kept"
        );
    }

    #[test]
    fn a_repeated_header_matches_when_any_value_does() {
        let fixture = Fixture::with(MESSAGES);
        assert_eq!(
            positions(&fixture, &equals("x-tag", "alpha")),
            [3],
            "the first value matches"
        );
        assert_eq!(
            positions(&fixture, &equals("x-tag", "beta")),
            [3],
            "the second value matches"
        );
    }

    #[test]
    fn and_or_and_not_combine_in_position_order() {
        let fixture = Fixture::with(MESSAGES);
        let both = Predicate::and(vec![exists("list-id"), exists("x-spam-flag")])
            .expect("and has arguments");
        assert_eq!(positions(&fixture, &both), [0], "and needs every argument");
        let either = Predicate::or(vec![exists("x-tag"), equals("x-spam-flag", "NO")])
            .expect("or has arguments");
        assert_eq!(
            positions(&fixture, &either),
            [1, 3],
            "or needs one argument"
        );
        assert_eq!(
            positions(&fixture, &negated(exists("x-spam-flag"))),
            [2, 3, 4, 6],
            "not keeps the messages without the header, including one that lacks it entirely"
        );
    }

    #[test]
    fn a_forged_authentication_results_outside_the_trust_set_never_matches() {
        assert_eq!(
            verdict_positions(
                &verdict(VerdictMethod::Dmarc, "pass"),
                Some(trust_mx_relay())
            ),
            Vec::<usize>::new(),
            "the forged dmarc=pass above the trusted dmarc=fail does not match"
        );
        assert_eq!(
            verdict_positions(
                &verdict(VerdictMethod::Dmarc, "fail"),
                Some(trust_mx_relay())
            ),
            [0],
            "the trusted header decides message 0"
        );
        assert_eq!(
            verdict_positions(&verdict(VerdictMethod::Spf, "pass"), Some(trust_mx_relay())),
            [0],
            "spf comes from the trusted header too"
        );
    }

    #[test]
    fn a_verdict_never_holds_without_a_trust_set() {
        for method in [
            VerdictMethod::Dmarc,
            VerdictMethod::Spf,
            VerdictMethod::Dkim,
            VerdictMethod::Compauth,
        ] {
            for word in ["pass", "fail", "softfail"] {
                assert_eq!(
                    verdict_positions(&verdict(method, word), None),
                    Vec::<usize>::new(),
                    "{method:?}={word} matches nothing without trust"
                );
            }
        }
    }

    #[test]
    fn an_idless_header_gives_a_verdict_only_above_the_first_external_hop() {
        let predicate = verdict(VerdictMethod::Dmarc, "pass");
        assert_eq!(
            verdict_positions(&predicate, Some(trust_mx_relay())),
            Vec::<usize>::new(),
            "an id-less header is untrusted by default"
        );
        let idless = trust_mx_relay().trust_idless_inside(true).clone();
        assert_eq!(
            verdict_positions(&predicate, Some(idless)),
            [1],
            "with the switch on, message 1 qualifies and message 2, below the hop, does not"
        );
    }

    #[test]
    fn filtered_positions_select_exactly_those_messages() {
        let fixture = Fixture::with(MESSAGES);
        let found = positions(&fixture, &exists("x-spam-flag"));
        let pipeline = Arc::new(Pipeline::new(vec![Column::Subject], 2));
        let subjects: Vec<String> = pipeline
            .select(&fixture.mailbox, Selection::Positions(found))
            .expect("every filtered position is in range")
            .flat_map(|result| {
                let assembled = result.expect("the batch is assembled");
                assembled
                    .column(0)
                    .as_string::<i32>()
                    .iter()
                    .map(|subject| subject.expect("every message has a subject").to_owned())
                    .collect::<Vec<_>>()
            })
            .collect();
        assert_eq!(
            subjects,
            ["Invoice 2024 due", "Re: lunch", "shouting"],
            "the selection reads the filtered messages in order"
        );
    }

    #[test]
    fn a_subject_filter_collects_no_received_or_authentication_results() {
        let fixture = Fixture::with(VERDICTS);
        let filter = Filter::new(&contains("subject", "forged")).expect("the predicate is valid");
        assert_eq!(
            selected(&fixture.mailbox, &filter),
            [0],
            "the forged message is found by its subject"
        );
        assert_eq!(
            filter.headers_collected(),
            3,
            "one Subject per message and none of the six Authentication-Results or Received"
        );
    }

    #[test]
    fn a_verdict_filter_collects_only_authentication_results_and_received() {
        let fixture = Fixture::with(VERDICTS);
        let filter = Filter::new(&verdict(VerdictMethod::Dmarc, "pass"))
            .expect("the predicate is valid")
            .with_trust(trust_mx_relay());
        let _found = selected(&fixture.mailbox, &filter);
        assert_eq!(
            filter.headers_collected(),
            6,
            "two of each of those headers across the three messages, no Subject"
        );
    }

    #[test]
    fn a_cancelled_token_stops_the_scan_and_collects_no_headers() {
        let fixture = Fixture::with(VERDICTS);
        let filter = Filter::new(&contains("subject", "forged")).expect("the predicate is valid");
        let token = CancelToken::new();
        token.cancel();
        let error = Narrowing::new()
            .filter(&filter)
            .select(&fixture.mailbox, Some(&token))
            .expect_err("the token is cancelled before the scan");
        assert!(
            matches!(
                error,
                MboxTurboError::Cancelled {
                    target: None,
                    written: 0
                }
            ),
            "cancellation names no target and nothing written"
        );
        assert_eq!(filter.headers_collected(), 0, "no message was read");
    }

    #[test]
    fn candidate_positions_limit_the_headers_collected() {
        let fixture = Fixture::with(VERDICTS);
        let filter = Filter::new(&contains("subject", "forged")).expect("the predicate is valid");
        let narrowed = Narrowing::new()
            .positions(vec![0])
            .filter(&filter)
            .select(&fixture.mailbox, None)
            .expect("position 0 is in range");
        assert_eq!(narrowed.count, 1, "message 0 matches");
        assert_eq!(
            filter.headers_collected(),
            1,
            "one Subject from the one candidate"
        );
    }

    #[test]
    fn a_mailbox_past_one_scan_chunk_is_narrowed_in_ascending_order() {
        use std::fmt::Write as _;

        const MESSAGES: usize = 4097 + 50;
        const FLAGGED: [usize; 6] = [7, 1007, 2007, 3007, 4007, MESSAGES - 1];
        let mut contents = String::new();
        for index in 0..MESSAGES {
            let flag = if FLAGGED.contains(&index) {
                "X-Spam-Flag: YES\n"
            } else {
                ""
            };
            write!(
                contents,
                "From a@example.com Mon Jan  1 00:00:00 2024\n\
Subject: m{index}\n{flag}\nbody\n\n"
            )
            .expect("writing to a string cannot fail");
        }
        let fixture = Fixture::with(&contents);
        let found = positions(&fixture, &exists("x-spam-flag"));
        assert_eq!(
            found, FLAGGED,
            "matches in the first chunk and past it come back in ascending order"
        );
    }

    #[test]
    fn out_of_range_positions_are_refused_before_the_date_step() {
        let fixture = Fixture::with(VERDICTS);
        let error = Narrowing::new()
            .positions(vec![1, 3, 9])
            .dates(DateBounds::new(Some(0), None))
            .select(&fixture.mailbox, None)
            .expect_err("position 3 is past a mailbox of 3");
        assert!(
            matches!(
                error,
                MboxTurboError::PositionOutOfRange {
                    position: 3,
                    len: 3
                }
            ),
            "the first out-of-range position in the order given is named"
        );
    }

    fn leaf_forms() -> Vec<(&'static str, Predicate)> {
        vec![
            (r#"{"op":"exists","header":"list-id"}"#, exists("list-id")),
            (
                r#"{"op":"equals","header":"x-spam-flag","value":"YES"}"#,
                equals("x-spam-flag", "YES"),
            ),
            (
                r#"{"op":"contains","header":"subject","value":"invoice"}"#,
                contains("subject", "invoice"),
            ),
            (
                r#"{"op":"starts_with","header":"from","value":"billing@"}"#,
                starts_with("from", "billing@"),
            ),
            (
                r#"{"op":"regex","header":"subject","pattern":"^Re: "}"#,
                Predicate::regex("subject", "^Re: ").expect("the pattern compiles"),
            ),
        ]
    }

    fn verdict_forms() -> Vec<(&'static str, Predicate)> {
        vec![
            (
                r#"{"op":"verdict","method":"dmarc","equals":"pass"}"#,
                verdict(VerdictMethod::Dmarc, "pass"),
            ),
            (
                r#"{"op":"verdict","method":"compauth","equals":"fail"}"#,
                verdict(VerdictMethod::Compauth, "fail"),
            ),
            (
                r#"{"op":"verdict","method":"spf","equals":"none"}"#,
                verdict(VerdictMethod::Spf, "none"),
            ),
            (
                r#"{"op":"verdict","method":"dkim","equals":"softfail"}"#,
                verdict(VerdictMethod::Dkim, "softfail"),
            ),
        ]
    }

    fn combinator_forms() -> Vec<(&'static str, Predicate)> {
        vec![
            (
                concat!(
                    r#"{"op":"and","args":["#,
                    r#"{"op":"exists","header":"a"},{"op":"exists","header":"b"}]}"#
                ),
                Predicate::and(vec![exists("a"), exists("b")]).expect("and has arguments"),
            ),
            (
                r#"{"op":"or","args":[{"op":"exists","header":"a"}]}"#,
                Predicate::or(vec![exists("a")]).expect("or has arguments"),
            ),
            (
                r#"{"op":"not","arg":{"op":"exists","header":"a"}}"#,
                negated(exists("a")),
            ),
        ]
    }

    #[test]
    fn json_forms_match_the_documented_table() {
        let table = [leaf_forms(), verdict_forms(), combinator_forms()].concat();
        for (json, predicate) in table {
            assert_eq!(
                Predicate::from_json(json).expect("the documented form parses"),
                predicate,
                "{json} reads as the predicate"
            );
            assert_eq!(
                predicate.to_json().expect("a predicate serializes"),
                json,
                "the predicate writes as {json}"
            );
        }
    }

    /// The path and fault of an `InvalidPredicate` error.
    fn invalid(error: MboxTurboError) -> (String, PredicateFault) {
        let MboxTurboError::InvalidPredicate { path, fault } = error else {
            panic!("expected InvalidPredicate, got {error:?}");
        };
        (path, *fault)
    }

    #[test]
    fn an_invalid_pattern_names_its_path_and_the_pattern() {
        let json = concat!(
            r#"{"op":"and","args":[{"op":"exists","header":"a"},"#,
            r#"{"op":"regex","header":"s","pattern":"("}]}"#
        );
        let (path, fault) =
            invalid(Predicate::from_json(json).expect_err("the second argument does not compile"));
        assert_eq!(path, "and[1].regex", "the path leads to the pattern");
        assert!(
            matches!(&fault, PredicateFault::Regex { pattern, .. } if pattern == "("),
            "the fault carries the pattern"
        );
    }

    #[test]
    fn an_empty_or_below_a_not_is_refused_with_its_path() {
        let (path, fault) = invalid(
            Predicate::from_json(r#"{"op":"not","arg":{"op":"or","args":[]}}"#)
                .expect_err("the or has no arguments"),
        );
        assert_eq!(path, "not.or", "the path leads through the not");
        assert!(
            matches!(fault, PredicateFault::EmptyList),
            "the fault is the empty list"
        );
    }

    #[test]
    fn the_constructors_and_the_filter_refuse_an_empty_and_or_or() {
        let (and_path, _fault) =
            invalid(Predicate::and(Vec::new()).expect_err("and has no arguments"));
        assert_eq!(and_path, "and", "the constructor names the and");
        let (or_path, fault) = invalid(
            Filter::new(&Predicate::Or { args: Vec::new() })
                .expect_err("a hand-built empty or does not reach a filter"),
        );
        assert_eq!(or_path, "or", "the filter names the or");
        assert!(
            matches!(fault, PredicateFault::EmptyList),
            "the fault is the empty list"
        );
    }

    #[test]
    fn text_that_is_not_a_predicate_is_a_json_fault() {
        let (path, fault) =
            invalid(Predicate::from_json(r#"{"op":"nope"}"#).expect_err("the operator is unknown"));
        assert_eq!(path, "json", "a JSON fault sits at the root");
        assert!(
            matches!(fault, PredicateFault::Json(_)),
            "an unknown operator is a JSON fault"
        );
    }

    #[test]
    fn a_pattern_past_the_size_limit_is_refused() {
        let (path, fault) = invalid(
            Predicate::regex("subject", r"(\pL{100}){100}")
                .expect_err("the pattern compiles past the size limit"),
        );
        assert_eq!(path, "regex", "the path names the pattern field");
        assert!(
            matches!(fault, PredicateFault::Regex { .. }),
            "the fault is a regex fault"
        );
    }

    fn leaf() -> impl Strategy<Value = Predicate> {
        let name = "[a-z][a-z-]{0,8}";
        let text = "\\PC{0,12}";
        let patterns = prop::sample::select(vec!["^a", "b$", "[0-9]+", "x|y"]);
        prop_oneof![
            name.prop_map(|header| Predicate::Exists { header }),
            (name, text).prop_map(|(header, value)| Predicate::Equals { header, value }),
            (name, text).prop_map(|(header, value)| Predicate::Contains { header, value }),
            (name, text).prop_map(|(header, value)| Predicate::StartsWith { header, value }),
            (name, patterns).prop_map(|(header, chosen)| Predicate::Regex {
                header,
                pattern: chosen.to_owned(),
            }),
            (
                prop::sample::select(vec![
                    VerdictMethod::Dmarc,
                    VerdictMethod::Spf,
                    VerdictMethod::Dkim,
                    VerdictMethod::Compauth,
                ]),
                text,
            )
                .prop_map(|(method, equals)| Predicate::Verdict { method, equals }),
        ]
    }

    fn tree() -> impl Strategy<Value = Predicate> {
        leaf().prop_recursive(4, 24, 4, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 1..4).prop_map(|args| Predicate::And { args }),
                prop::collection::vec(inner.clone(), 1..4).prop_map(|args| Predicate::Or { args }),
                inner.prop_map(|arg| Predicate::Not { arg: Box::new(arg) }),
            ]
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn a_predicate_survives_a_json_round_trip(predicate in tree()) {
            let json = predicate.to_json().expect("a predicate serializes");
            let back = Predicate::from_json(&json).expect("written JSON reads back");
            prop_assert_eq!(&back, &predicate, "from_json(to_json(p)) is p");
            prop_assert_eq!(
                back.to_json().expect("a predicate serializes"),
                json,
                "to_json(from_json(s)) is s for the canonical s"
            );
        }

        #[test]
        fn filtered_positions_are_ascending_and_in_range(predicate in tree()) {
            let fixture = Fixture::with(MESSAGES);
            let found = positions(&fixture, &predicate);
            prop_assert!(
                found.windows(2).all(|pair| matches!(pair, [first, second] if first < second)),
                "positions {found:?} ascend strictly"
            );
            prop_assert!(
                found.iter().all(|&position| position < 7),
                "positions {found:?} lie inside the seven-message mailbox"
            );
        }
    }
}
