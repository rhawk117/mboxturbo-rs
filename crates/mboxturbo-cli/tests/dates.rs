//! `mboxturbo export --since` and `--until` select messages by their index date, report how many
//! undated messages the bounds excluded, and exit 64 for a bound that is not a date.

#[cfg(test)]
mod dates {
    use std::fs;
    use std::path::PathBuf;
    use std::process::{Command, Output};

    use serde_json::Value;
    use tempfile::TempDir;

    /// Positions 0 to 2 are at midnight UTC on 1 to 3 January 2024, 3 has no Date header, 4 has
    /// a Date that does not parse, and 5 is 12:00 at +02:00 on 4 January, which is 10:00 UTC.
    const MAILBOX: &str = concat!(
        "From a@example.com Mon Jan  1 00:00:00 2024\n",
        "Date: Mon, 1 Jan 2024 00:00:00 +0000\nSubject: zero\n\nbody zero\n\n",
        "From b@example.com Mon Jan  1 00:00:00 2024\n",
        "Date: Tue, 2 Jan 2024 00:00:00 +0000\nSubject: one\n\nbody one\n\n",
        "From c@example.com Mon Jan  1 00:00:00 2024\n",
        "Date: Wed, 3 Jan 2024 00:00:00 +0000\nSubject: two\n\nbody two\n\n",
        "From d@example.com Mon Jan  1 00:00:00 2024\n",
        "Subject: three\n\nbody three\n\n",
        "From e@example.com Mon Jan  1 00:00:00 2024\n",
        "Date: not a date\nSubject: four\n\nbody four\n\n",
        "From f@example.com Mon Jan  1 00:00:00 2024\n",
        "Date: Thu, 4 Jan 2024 12:00:00 +0200\nSubject: five\n\nbody five\n\n",
    );

    const SCHEMA: &str = include_str!("../schema/events-v1.json");

    /// A temporary directory holding the six-message mailbox.
    struct Fixture {
        dir: TempDir,
        mbox: PathBuf,
    }

    impl Fixture {
        /// Runs `mboxturbo export <mailbox> --format jsonl -o <out> <args>`.
        fn export(&self, args: &[&str]) -> Output {
            let mbox = self.mbox.to_str().expect("the fixture path is UTF-8");
            let target = self.target();
            run(&[&["export", mbox, "--format", "jsonl", "-o", &target], args].concat())
        }

        /// The positions of the exported messages, in file order.
        fn exported(&self, args: &[&str]) -> Vec<u64> {
            let output = self.export(&[&["--columns", "position", "--overwrite"], args].concat());
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
            fs::write(&mbox, MAILBOX).expect("the fixture mailbox is written");
            Self { dir, mbox }
        }

        fn target(&self) -> String {
            self.dir
                .path()
                .join("out.jsonl")
                .to_str()
                .expect("the fixture path is UTF-8")
                .to_owned()
        }
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

    /// The `summary` event of a `--json` run, read from the last line of standard output.
    fn summary(output: &Output) -> Value {
        assert_eq!(code(output), 0_i32, "export succeeds: {}", stderr(output));
        let stdout = String::from_utf8_lossy(&output.stdout);
        let last = stdout.lines().last().expect("a run writes events");
        serde_json::from_str(last).expect("the last event is JSON")
    }

    /// The `summary` branch of the event schema.
    fn summary_schema() -> Value {
        let schema: Value = serde_json::from_str(SCHEMA).expect("the schema is JSON");
        schema["oneOf"]
            .as_array()
            .expect("the schema lists its events")
            .iter()
            .find(|branch| branch["title"] == "summary")
            .expect("the schema has a summary event")
            .clone()
    }

    #[test]
    fn since_is_inclusive_to_the_second_and_until_exclusive() {
        let fixture = Fixture::new();
        assert_eq!(
            fixture.exported(&[
                "--since",
                "2024-01-02T00:00:00Z",
                "--until",
                "2024-01-03T00:00:00Z"
            ]),
            [1],
            "a message dated exactly at since is kept and one dated exactly at until is not"
        );
        assert_eq!(
            fixture.exported(&["--since", "2024-01-02T00:00:01Z"]),
            [2, 5],
            "one second past a message's date drops it"
        );
        assert_eq!(
            fixture.exported(&["--until", "2024-01-01T23:59:59Z"]),
            [0],
            "an until one second before a message's date drops it"
        );
    }

    #[test]
    fn an_open_bound_leaves_that_side_unbounded() {
        let fixture = Fixture::new();
        assert_eq!(
            fixture.exported(&["--since", "2024-01-03T00:00:00Z"]),
            [2, 5],
            "no until keeps every later dated message"
        );
        assert_eq!(
            fixture.exported(&["--until", "2024-01-02T00:00:00Z"]),
            [0],
            "no since keeps every earlier dated message"
        );
    }

    #[test]
    fn a_plain_date_is_midnight_utc() {
        let fixture = Fixture::new();
        assert_eq!(
            fixture.exported(&["--since", "2024-01-02", "--until", "2024-01-03"]),
            [1],
            "2024-01-02 is 2024-01-02T00:00:00Z, kept; 2024-01-03 is exclusive"
        );
    }

    #[test]
    fn an_offset_compares_instants_not_wall_clocks() {
        let fixture = Fixture::new();
        assert_eq!(
            fixture.exported(&["--since", "2024-01-04T12:00:00+02:00"]),
            [5],
            "12:00 at +02:00 is the instant of message 5, so since keeps it"
        );
        assert_eq!(
            fixture.exported(&["--since", "2024-01-04T10:00:00-02:00"]),
            Vec::<u64>::new(),
            "10:00 at -02:00 is 12:00 UTC, later than message 5"
        );
        assert_eq!(
            fixture.exported(&["--until", "2024-01-04T11:00:00+02:00"]),
            [0, 1, 2],
            "11:00 at +02:00 is 09:00 UTC, before message 5"
        );
    }

    #[test]
    fn a_fraction_of_a_second_rounds_the_bound_up() {
        let fixture = Fixture::new();
        assert_eq!(
            fixture.exported(&["--since", "2024-01-02T00:00:00.5Z"]),
            [2, 5],
            "a since half a second late is the next whole second, so message 1 is dropped"
        );
        assert_eq!(
            fixture.exported(&["--until", "2024-01-02T00:00:00.5Z"]),
            [0, 1],
            "an until half a second late is the next whole second, so message 1 is kept"
        );
    }

    /// Checks that the schema declares `excluded_undated` as an optional non-negative integer
    /// and every key of `event`.
    fn assert_declared_by_schema(event: &Value) {
        let schema = summary_schema();
        let declared = &schema["properties"]["excluded_undated"];
        assert_eq!(
            (declared["type"].as_str(), declared["minimum"].as_u64()),
            (Some("integer"), Some(0)),
            "the schema declares excluded_undated as a non-negative integer"
        );
        assert!(
            !schema["required"]
                .as_array()
                .expect("required is a list")
                .contains(&Value::from("excluded_undated")),
            "the schema leaves excluded_undated optional"
        );
        let known = schema["properties"]
            .as_object()
            .expect("the summary schema lists its properties");
        assert!(
            event
                .as_object()
                .expect("an event is an object")
                .keys()
                .all(|key| known.contains_key(key)),
            "every summary key is declared by the schema: {event}"
        );
    }

    #[test]
    fn the_summary_event_counts_the_undated_messages_a_bound_excluded() {
        let fixture = Fixture::new();
        let output = fixture.export(&["--json", "--since", "2024-01-01"]);
        let event = summary(&output);
        assert_declared_by_schema(&event);
        assert_eq!(
            (
                event["excluded_undated"].as_u64(),
                event["messages"].as_u64()
            ),
            (Some(2), Some(4)),
            "two undated messages are excluded and four dated ones kept"
        );
    }

    #[test]
    fn the_summary_event_has_no_count_without_a_bound() {
        let fixture = Fixture::new();
        let event = summary(&fixture.export(&["--json"]));
        assert!(
            event.get("excluded_undated").is_none(),
            "no bound, no count: {event}"
        );
    }

    #[test]
    fn the_summary_line_says_how_many_undated_messages_were_excluded() {
        let fixture = Fixture::new();
        let bounded = fixture.export(&["--until", "2024-01-03"]);
        assert!(
            stderr(&bounded).contains("(2 undated excluded)"),
            "the line carries the count: {}",
            stderr(&bounded)
        );
        let unbounded = fixture.export(&["--overwrite"]);
        assert!(
            !stderr(&unbounded).contains("undated"),
            "no bound, no count: {}",
            stderr(&unbounded)
        );
    }

    #[test]
    fn a_date_bound_narrows_the_selected_positions() {
        let fixture = Fixture::new();
        assert_eq!(
            fixture.exported(&["--select", "0..3", "--since", "2024-01-02"]),
            [1, 2],
            "a message must pass both the selection and the bound"
        );
        assert_eq!(
            fixture.exported(&["--select", "5,1,0", "--since", "2024-01-02"]),
            [1, 5],
            "positions listed out of order come out in mailbox order"
        );
        assert_eq!(
            fixture.exported(&["--select", "3,4", "--since", "2024-01-01"]),
            Vec::<u64>::new(),
            "undated messages selected by position are still excluded by a bound"
        );
    }

    #[test]
    fn a_malformed_when_exits_64_naming_the_flag_and_value() {
        let fixture = Fixture::new();
        for (flag, value) in [("--since", "soon"), ("--until", "2024-02-30")] {
            let output = fixture.export(&[flag, value]);
            assert_eq!(code(&output), 64_i32, "{flag} {value} is usage");
            assert!(
                stderr(&output).contains(flag) && stderr(&output).contains(value),
                "the message names the flag and the value: {}",
                stderr(&output)
            );
        }
    }
}
