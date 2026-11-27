//! `mboxturbo export --where` and `--where-file` keep the messages a JSON predicate matches,
//! intersect with the other filters, and exit 64 for a predicate that is not valid.

#[cfg(test)]
mod common;

#[cfg(test)]
mod predicates {
    use std::fs;
    use std::path::PathBuf;
    use std::process::{Command, Output};

    use serde_json::Value;
    use tempfile::TempDir;

    use crate::common::{schema, violations};

    const FORGED: &str =
        "Authentication-Results: evil.example; dmarc=pass header.from=example.org\n";
    const GENUINE: &str =
        "Authentication-Results: mx.example.org; dmarc=fail header.from=example.org\n";
    const PASSING: &str =
        "Authentication-Results: mx.example.org; dmarc=pass header.from=example.org\n";

    const SUBJECT_HAS_O: &str = r#"{"op":"contains","header":"subject","value":"o"}"#;

    /// A temporary directory holding the six-message mailbox.
    struct Fixture {
        dir: TempDir,
        mbox: PathBuf,
    }

    impl Fixture {
        /// Runs `mboxturbo export <mailbox> --format jsonl -o <out> <args>`.
        fn export(&self, args: &[&str]) -> Output {
            let mbox = self.mbox.to_str().expect("the fixture path is UTF-8");
            let target = self.path("out.jsonl");
            run(&[
                &[
                    "export",
                    mbox,
                    "--format",
                    "jsonl",
                    "-o",
                    &target,
                    "--overwrite",
                ],
                args,
            ]
            .concat())
        }

        /// The positions of the exported messages, in file order.
        fn exported(&self, args: &[&str]) -> Vec<u64> {
            let output = self.export(&[&["--columns", "position"], args].concat());
            assert_eq!(
                code(&output),
                0_i32,
                "the export succeeds: {}",
                stderr(&output)
            );
            fs::read_to_string(self.dir.path().join("out.jsonl"))
                .expect("the export wrote its output")
                .lines()
                .map(|line| {
                    let row: Value = serde_json::from_str(line).expect("a row is JSON");
                    row["position"].as_u64().expect("a row has its position")
                })
                .collect()
        }

        fn new() -> Self {
            let dir = TempDir::new().expect("a temporary directory is created");
            let mbox = dir.path().join("mail.mbox");
            fs::write(&mbox, mailbox()).expect("the fixture mailbox is written");
            Self { dir, mbox }
        }

        fn path(&self, name: &str) -> String {
            self.dir
                .path()
                .join(name)
                .to_str()
                .expect("the fixture path is UTF-8")
                .to_owned()
        }
    }

    /// The message shapes of `test_select.py`: positions 0 to 5 with subjects `zero` to `five`,
    /// position 3 and 5 undated, and position 4 dated 4 January at +0100.
    fn mailbox() -> String {
        let message = |lines: &[&str]| {
            format!(
                "From a@example.com Mon Jan  1 00:00:00 2024\n{}\n\nbody\n\n",
                lines.join("\n")
            )
        };
        [
            message(&[
                "Date: Mon, 01 Jan 2024 00:00:00 +0000",
                "Subject: zero",
                format!("{FORGED}{GENUINE}").trim_end(),
            ]),
            message(&[
                "Date: Tue, 02 Jan 2024 00:00:00 +0000",
                "Subject: one",
                PASSING.trim_end(),
            ]),
            message(&[
                "Date: Wed, 03 Jan 2024 00:00:00 +0000",
                "Subject: two",
                FORGED.trim_end(),
            ]),
            message(&["Subject: three"]),
            message(&["Date: Thu, 04 Jan 2024 00:00:00 +0100", "Subject: four"]),
            message(&["Subject: five"]),
        ]
        .concat()
    }

    fn run(args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_mboxturbo"))
            .args(args)
            .env("NO_COLOR", "1")
            .output()
            .expect("the built mboxturbo binary runs")
    }

    fn code(output: &Output) -> i32 {
        output
            .status
            .code()
            .expect("the process exited rather than being signalled")
    }

    fn stderr(output: &Output) -> String {
        String::from_utf8_lossy(&output.stderr).into_owned()
    }

    /// Asserts a `--json` run that failed with 64 and whose last event is a valid `error`.
    fn assert_usage_error_event(fixture: &Fixture, args: &[&str]) -> String {
        let output = fixture.export(&[&["--json"], args].concat());
        assert_eq!(code(&output), 64_i32, "exit code: {}", stderr(&output));
        let stdout = String::from_utf8_lossy(&output.stdout);
        let last: Value = serde_json::from_str(stdout.lines().last().expect("an event is written"))
            .expect("the last event is JSON");
        assert_eq!(last["event"], "error", "the stream ends with an error");
        assert_eq!(last["code"], 64_i32, "the event carries code 64");
        let found = violations(&schema(), &last);
        assert!(found.is_empty(), "the event breaks the schema: {found:?}");
        last["message"]
            .as_str()
            .expect("the message is a string")
            .to_owned()
    }

    /// Pins the result against #19's Python `test_a_predicate_keeps_the_matching_rows` in
    /// `crates/mboxturbo-py/tests/integration/select/test_select.py`, which selects
    /// `header('subject').contains('o')` on these message shapes and expects `[0, 1, 2, 4]`.
    #[test]
    fn a_header_predicate_keeps_the_matching_messages_as_the_python_select_does() {
        let fixture = Fixture::new();
        assert_eq!(
            fixture.exported(&["--where", SUBJECT_HAS_O]),
            [0, 1, 2, 4],
            "the subjects zero, one, two and four contain an o"
        );
    }

    #[test]
    fn where_file_gives_the_same_result_as_where() {
        let fixture = Fixture::new();
        fs::write(fixture.path("pred.json"), SUBJECT_HAS_O).expect("the predicate is written");
        let path = fixture.path("pred.json");
        assert_eq!(
            fixture.exported(&["--where-file", &path]),
            fixture.exported(&["--where", SUBJECT_HAS_O]),
            "the file holds the same predicate"
        );
    }

    #[test]
    fn a_predicate_intersects_with_select_and_since_as_the_python_select_does() {
        let fixture = Fixture::new();
        assert_eq!(
            fixture.exported(&[
                "--select",
                "0,1,2,4,5",
                "--since",
                "2024-01-03",
                "--where",
                SUBJECT_HAS_O
            ]),
            [2, 4],
            "only positions chosen, dated since 3 January and matching survive"
        );
        assert_eq!(
            fixture.exported(&["--select", "1..3", "--where", SUBJECT_HAS_O]),
            [1, 2],
            "--select narrows the matches"
        );
    }

    #[test]
    fn a_predicate_that_matches_nothing_exports_nothing() {
        let fixture = Fixture::new();
        let none = r#"{"op":"equals","header":"subject","value":"absent"}"#;
        assert_eq!(
            fixture.exported(&["--where", none]),
            Vec::<u64>::new(),
            "no message matches"
        );
    }

    #[test]
    fn bad_json_exits_64_with_an_error_event() {
        let fixture = Fixture::new();
        let message = assert_usage_error_event(&fixture, &["--where", "{not json"]);
        assert!(
            message.contains("json"),
            "the message names the predicate path: {message}"
        );
    }

    #[test]
    fn an_invalid_predicate_exits_64_with_an_error_event() {
        let fixture = Fixture::new();
        let message = assert_usage_error_event(&fixture, &["--where", r#"{"op":"and","args":[]}"#]);
        assert!(
            message.contains("and"),
            "the message names the faulty operator: {message}"
        );
    }

    #[test]
    fn an_unreadable_where_file_exits_74_naming_it() {
        let fixture = Fixture::new();
        let missing = fixture.path("absent.json");
        let output = fixture.export(&["--where-file", &missing]);
        assert_eq!(
            code(&output),
            74_i32,
            "an unreadable predicate file is an I/O error, like an unreadable select file"
        );
        assert!(
            stderr(&output).contains("absent.json"),
            "the message names the file: {}",
            stderr(&output)
        );
    }

    #[test]
    fn where_conflicts_with_where_file() {
        let fixture = Fixture::new();
        let path = fixture.path("pred.json");
        let output = fixture.export(&["--where", SUBJECT_HAS_O, "--where-file", &path]);
        assert_eq!(code(&output), 64_i32, "conflicting flags are usage");
        assert!(
            stderr(&output).contains("cannot be used with"),
            "clap names the conflict: {}",
            stderr(&output)
        );
    }
}
