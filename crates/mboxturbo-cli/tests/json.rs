//! `mboxturbo export --json` writes only versioned events on standard output, in a fixed order,
//! each valid against `schema/events-v1.json`, and ends with a summary or an error.

#[cfg(test)]
mod json {
    use std::fs;
    use std::path::PathBuf;
    use std::process::{Command, Output};

    use serde_json::Value;
    use tempfile::TempDir;

    const MAILBOX: &str = concat!(
        "From a@example.com Mon Jan  1 00:00:00 2024\n",
        "Subject: zero\nFrom: a@example.com\n\nbody zero\n\n",
        "From b@example.com Mon Jan  1 00:00:00 2024\n",
        "Subject: one\nFrom: b@example.com\n\nbody one\n\n",
        "From c@example.com Mon Jan  1 00:00:00 2024\n",
        "Subject: two\nFrom: c@example.com\n\nbody two\n\n",
        "From d@example.com Mon Jan  1 00:00:00 2024\n",
        "Subject: three\nFrom: d@example.com\n\nbody three\n\n",
    );

    const SCHEMA: &str = include_str!("../schema/events-v1.json");

    /// Keywords that only annotate: the validator accepts and ignores them.
    const ANNOTATIONS: [&str; 3] = ["$schema", "title", "description"];

    /// A temporary directory holding a four-message mailbox.
    struct Fixture {
        dir: TempDir,
        mbox: PathBuf,
    }

    impl Fixture {
        /// Runs `mboxturbo export <mailbox> --json <args>`.
        fn export(&self, args: &[&str]) -> Output {
            let mbox = self.mbox.to_str().expect("the fixture path is UTF-8");
            run(&[&["export", mbox, "--json"], args].concat())
        }

        fn new() -> Self {
            let dir = TempDir::new().expect("a temporary directory is created");
            let mbox = dir.path().join("mail.mbox");
            fs::write(&mbox, MAILBOX).expect("the fixture mailbox is written");
            Self { dir, mbox }
        }

        /// The string form of a path inside the fixture directory.
        fn target(&self, name: &str) -> String {
            self.dir
                .path()
                .join(name)
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

    /// Every line of standard output parsed as JSON and checked against the schema.
    fn events(output: &Output) -> Vec<Value> {
        let schema = schema();
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|line| {
                let event: Value = serde_json::from_str(line)
                    .unwrap_or_else(|error| panic!("stdout line is not JSON ({error}): {line}"));
                let violations = violations(&schema, &event);
                assert!(
                    violations.is_empty(),
                    "event {line} breaks the schema: {violations:?}"
                );
                event
            })
            .collect()
    }

    fn schema() -> Value {
        serde_json::from_str(SCHEMA).expect("the schema is JSON")
    }

    /// The `event` name of each event.
    fn names(events: &[Value]) -> Vec<&str> {
        events
            .iter()
            .map(|event| event["event"].as_str().expect("every event is named"))
            .collect()
    }

    /// The ways `value` breaks `schema`, none when it is valid. Supports exactly the keywords
    /// `events-v1.json` uses; any other keyword panics so the schema cannot outgrow this check.
    fn violations(schema: &Value, value: &Value) -> Vec<String> {
        let keywords = schema.as_object().expect("a schema is an object");
        let mut found = Vec::new();
        for (keyword, argument) in keywords {
            match keyword.as_str() {
                key if ANNOTATIONS.contains(&key) => {},
                "type" => found.extend(check_type(argument, value)),
                "required" => found.extend(check_required(argument, value)),
                "properties" => found.extend(check_properties(argument, value)),
                "additionalProperties" => {
                    found.extend(check_additional(keywords, argument, value));
                },
                "const" => {
                    found.extend((argument != value).then(|| format!("{value} is not {argument}")));
                },
                "enum" => found.extend(check_enum(argument, value)),
                "oneOf" => found.extend(check_one_of(argument, value)),
                other => panic!("the validator does not know the keyword `{other}`"),
            }
        }
        found
    }

    fn check_type(expected: &Value, value: &Value) -> Vec<String> {
        let matches = match expected.as_str().expect("a type is a string") {
            "object" => value.is_object(),
            "string" => value.is_string(),
            "integer" => value.is_u64() || value.is_i64(),
            other => panic!("the validator does not know the type `{other}`"),
        };
        (!matches)
            .then(|| format!("{value} is not of type {expected}"))
            .into_iter()
            .collect()
    }

    fn check_required(required: &Value, value: &Value) -> Vec<String> {
        let Some(object) = value.as_object() else {
            return Vec::new();
        };
        required
            .as_array()
            .expect("required is an array")
            .iter()
            .map(|member| member.as_str().expect("a required name is a string"))
            .filter(|member| !object.contains_key(*member))
            .map(|member| format!("`{member}` is missing"))
            .collect()
    }

    fn check_properties(properties: &Value, value: &Value) -> Vec<String> {
        let Some(object) = value.as_object() else {
            return Vec::new();
        };
        let mut found = Vec::new();
        for (member, subschema) in properties.as_object().expect("properties is an object") {
            if let Some(content) = object.get(member) {
                found.extend(
                    violations(subschema, content)
                        .into_iter()
                        .map(|reason| format!("`{member}`: {reason}")),
                );
            }
        }
        found
    }

    fn check_additional(
        keywords: &serde_json::Map<String, Value>,
        argument: &Value,
        value: &Value,
    ) -> Vec<String> {
        assert_eq!(
            argument,
            &Value::Bool(false),
            "the validator supports only additionalProperties: false"
        );
        let Some(object) = value.as_object() else {
            return Vec::new();
        };
        let known = keywords
            .get("properties")
            .and_then(Value::as_object)
            .expect("additionalProperties: false comes with properties");
        object
            .keys()
            .filter(|member| !known.contains_key(*member))
            .map(|member| format!("`{member}` is not allowed"))
            .collect()
    }

    fn check_enum(allowed: &Value, value: &Value) -> Vec<String> {
        let listed = allowed
            .as_array()
            .expect("enum is an array")
            .contains(value);
        (!listed)
            .then(|| format!("{value} is not one of {allowed}"))
            .into_iter()
            .collect()
    }

    fn check_one_of(subschemas: &Value, value: &Value) -> Vec<String> {
        let matching = subschemas
            .as_array()
            .expect("oneOf is an array")
            .iter()
            .filter(|subschema| violations(subschema, value).is_empty())
            .count();
        (matching != 1)
            .then(|| format!("{matching} subschemas match, not exactly one"))
            .into_iter()
            .collect()
    }

    /// The events of a successful export, checked for order and for the counts they share.
    fn assert_export_events(output: &Output, format: &str, messages: u64) -> Vec<Value> {
        assert_eq!(code(output), 0_i32, "export succeeds: {}", stderr(output));
        let events = events(output);
        let names = names(&events);
        let [start, index, progress @ .., file, summary] = names.as_slice() else {
            panic!("a successful stream has at least five events: {names:?}");
        };
        assert_eq!(
            (*start, *index, *file, *summary),
            ("start", "index", "file", "summary"),
            "the stream is start, index, progress, file, summary"
        );
        assert!(
            !progress.is_empty() && progress.iter().all(|name| *name == "progress"),
            "one or more progress events sit between index and file: {names:?}"
        );
        assert_eq!(events[0]["format"], format, "start names the format");
        assert_eq!(
            events[0]["selected"], messages,
            "start counts the selection"
        );
        let last_progress = events.iter().rev().nth(2).expect("a progress event exists");
        assert_eq!(
            (
                last_progress["messages"].as_u64(),
                last_progress["total"].as_u64()
            ),
            (Some(messages), Some(messages)),
            "the last progress event is complete"
        );
        events
    }

    #[test]
    fn every_format_writes_a_valid_ordered_stream_ending_in_a_summary() {
        for format in ["arrow", "csv", "eml", "jsonl", "mbox", "parquet"] {
            let fixture = Fixture::new();
            let target = fixture.target(&format!("out.{format}"));
            let output = fixture.export(&["--format", format, "-o", &target]);
            let events = assert_export_events(&output, format, 4);
            let summary = events.last().expect("the stream has events");
            assert_eq!(
                summary["messages"], 4_u64,
                "{format}: summary counts messages"
            );
            assert_eq!(
                summary["path"], target,
                "{format}: summary names the output"
            );
            let file = events
                .iter()
                .rev()
                .nth(1)
                .expect("the stream has a file event");
            assert_eq!(file["path"], target, "{format}: file names the output");
            assert_eq!(file["format"], format, "{format}: file names the format");
            assert_eq!(file["messages"], 4_u64, "{format}: file counts messages");
        }
    }

    #[test]
    fn an_eml_export_emits_one_file_event_for_its_directory() {
        let fixture = Fixture::new();
        let target = fixture.target("out");
        let output = fixture.export(&["--format", "eml", "-o", &target]);
        let events = assert_export_events(&output, "eml", 4);
        assert_eq!(
            names(&events)
                .iter()
                .filter(|name| **name == "file")
                .count(),
            1,
            "four messages, one file event"
        );
    }

    #[test]
    fn start_counts_only_the_selected_messages() {
        let fixture = Fixture::new();
        let target = fixture.target("out.csv");
        let output = fixture.export(&["--format", "csv", "-o", &target, "--select", "1..3"]);
        let events = assert_export_events(&output, "csv", 2);
        assert_eq!(
            events[0]["selected"], 2_u64,
            "positions 1 and 2 are selected"
        );
    }

    #[test]
    fn the_index_event_says_rebuilt_then_loaded() {
        let fixture = Fixture::new();
        let index = fixture.target("mail.idx");
        let origins: Vec<Value> = ["first.csv", "second.csv"]
            .iter()
            .map(|name| {
                let target = fixture.target(name);
                let output = fixture.export(&["--format", "csv", "-o", &target, "--index", &index]);
                events(&output)[1]["origin"].clone()
            })
            .collect();
        assert_eq!(
            origins,
            ["rebuilt", "loaded"],
            "the first open builds the index and the second reads it"
        );
    }

    #[test]
    fn json_with_stdout_output_exits_64_with_one_error_event_and_no_data() {
        let fixture = Fixture::new();
        let output = fixture.export(&["--format", "csv", "-o", "-"]);
        assert_eq!(code(&output), 64_i32, "--json with -o - is usage");
        let events = events(&output);
        assert_eq!(
            names(&events),
            ["error"],
            "the only line is the error event"
        );
        assert_eq!(events[0]["code"], 64_u64, "the event carries the exit code");
    }

    /// Asserts a failed run whose last event is an `error` carrying `expected` and the stderr line.
    fn assert_error_event(output: &Output, expected: i32) -> Vec<Value> {
        assert_eq!(code(output), expected, "exit code: {}", stderr(output));
        let events = events(output);
        let last = events.last().expect("a failed run writes an event");
        assert_eq!(last["event"], "error", "the stream ends with an error");
        assert_eq!(last["code"], expected, "the event carries the exit code");
        assert_eq!(
            last["message"].as_str().expect("the message is a string"),
            stderr(output).trim_end(),
            "the message is the stderr line"
        );
        events
    }

    #[test]
    fn a_usage_error_before_the_mailbox_opens_is_only_an_error_event() {
        let fixture = Fixture::new();
        let target = fixture.target("out.csv");
        let output = fixture.export(&["--format", "csv", "-o", &target, "--columns", "nope"]);
        let events = assert_error_event(&output, 64);
        assert_eq!(names(&events), ["error"], "nothing was started");
    }

    #[test]
    fn a_missing_mailbox_ends_in_an_error_event_with_code_66() {
        let fixture = Fixture::new();
        let missing = fixture.target("absent.mbox");
        let target = fixture.target("out.csv");
        let output = run(&[
            "export", &missing, "--json", "--format", "csv", "-o", &target,
        ]);
        let events = assert_error_event(&output, 66);
        assert_eq!(names(&events), ["error"], "the mailbox never opened");
    }

    #[test]
    fn an_existing_target_ends_in_an_error_event_with_code_73() {
        let fixture = Fixture::new();
        let target = fixture.target("out.csv");
        fs::write(&target, "keep me").expect("the existing output is written");
        let output = fixture.export(&["--format", "csv", "-o", &target]);
        let events = assert_error_event(&output, 73);
        assert_eq!(
            names(&events)[..2],
            ["start", "index"],
            "the export had started"
        );
    }

    #[test]
    fn a_missing_output_directory_ends_in_an_error_event_with_code_74() {
        let fixture = Fixture::new();
        let target = fixture.target("no/such/dir/out.csv");
        let output = fixture.export(&["--format", "csv", "-o", &target]);
        let events = assert_error_event(&output, 74);
        assert_eq!(
            names(&events)[..2],
            ["start", "index"],
            "the export had started"
        );
    }

    #[test]
    fn a_corrupt_index_ends_in_an_error_event_with_code_65() {
        let fixture = Fixture::new();
        let index = fixture.target("mail.idx");
        let first = fixture.target("first.csv");
        let build = fixture.export(&["--format", "csv", "-o", &first, "--index", &index]);
        assert_eq!(
            code(&build),
            0_i32,
            "the index is built: {}",
            stderr(&build)
        );
        let mut damaged = fs::read(&index).expect("the index file was written");
        damaged[60] ^= 0xFF;
        fs::write(&index, &damaged).expect("the index file is damaged");
        let second = fixture.target("second.csv");
        let output = fixture.export(&["--format", "csv", "-o", &second, "--index", &index]);
        let events = assert_error_event(&output, 65);
        assert_eq!(
            names(&events).last(),
            Some(&"error"),
            "the stream ends in the error"
        );
    }

    #[test]
    fn a_parse_failure_with_json_in_argv_writes_one_error_event_with_code_64() {
        let output = run(&["export", "--json", "--no-such-flag"]);
        assert_eq!(code(&output), 64_i32, "an unknown flag is usage");
        let events = events(&output);
        assert_eq!(
            names(&events),
            ["error"],
            "the only line is the error event"
        );
        assert_eq!(events[0]["code"], 64_u64, "the event carries the exit code");
        assert!(!stderr(&output).is_empty(), "clap still reports on stderr");
    }

    #[test]
    fn without_json_standard_output_carries_no_events() {
        let fixture = Fixture::new();
        let mbox = fixture.mbox.to_str().expect("the fixture path is UTF-8");
        let output = run(&["export", mbox, "--format", "jsonl", "-o", "-"]);
        assert_eq!(code(&output), 0_i32, "export succeeds: {}", stderr(&output));
        let first = String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()
            .expect("the export wrote a line")
            .to_owned();
        let row: Value = serde_json::from_str(&first).expect("a jsonl row is JSON");
        assert!(row.get("event").is_none(), "the row is data, not an event");
    }

    #[test]
    fn the_validator_rejects_what_the_schema_forbids() {
        let schema = schema();
        let bad = [
            r#"{"v":1,"event":"index","origin":"loaded","extra":true}"#,
            r#"{"v":1,"event":"progress","messages":"1","total":1,"bytes":1}"#,
            r#"{"v":2,"event":"index","origin":"loaded"}"#,
            r#"{"v":1,"event":"index"}"#,
        ];
        for text in bad {
            let event: Value = serde_json::from_str(text).expect("the sample is JSON");
            assert!(
                !violations(&schema, &event).is_empty(),
                "{text} must not validate"
            );
        }
    }

    #[test]
    #[should_panic(expected = "does not know the keyword")]
    fn the_validator_fails_on_a_keyword_it_does_not_know() {
        let schema: Value = serde_json::from_str(r#"{"minimum":1}"#).expect("the sample is JSON");
        let outcome = violations(&schema, &Value::Null);
        assert!(outcome.is_empty(), "unreachable: the keyword panics first");
    }
}
