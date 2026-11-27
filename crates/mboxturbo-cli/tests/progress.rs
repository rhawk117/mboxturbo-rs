//! What `mboxturbo export` prints on standard error: no escape codes unless styling is on, one
//! summary line and an index note unless `--quiet`, and an unchanged `--json` stream.

#[cfg(test)]
mod progress {
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

    /// Event fields that differ between runs: timings and the per-run paths.
    const VOLATILE: [&str; 4] = ["elapsed_ms", "path", "output", "mailbox"];

    /// The byte that starts every terminal escape sequence.
    const ESCAPE: u8 = 0x1B;

    const UNSET: Colors = Colors {
        clicolor_force: None,
        no_color: None,
    };
    const NO_COLOR: Colors = Colors {
        clicolor_force: None,
        no_color: Some("1"),
    };
    const FORCE_ZERO: Colors = Colors {
        clicolor_force: Some("0"),
        no_color: None,
    };
    const FORCE_ONE: Colors = Colors {
        clicolor_force: Some("1"),
        no_color: None,
    };

    /// The colour variables of one run: `None` leaves the variable unset.
    #[derive(Clone, Copy)]
    struct Colors {
        clicolor_force: Option<&'static str>,
        no_color: Option<&'static str>,
    }

    /// A temporary directory holding a four-message mailbox.
    struct Fixture {
        dir: TempDir,
        mbox: PathBuf,
    }

    impl Fixture {
        /// Runs `mboxturbo export <mailbox> --format csv -o <name> <args>`.
        fn export(&self, colors: Colors, name: &str, args: &[&str]) -> Output {
            let mbox = self.mbox.to_str().expect("the fixture path is UTF-8");
            let path = self.dir.path().join(name);
            let target = path.to_str().expect("the fixture path is UTF-8");
            let base = ["export", mbox, "--format", "csv", "-o", target];
            run(colors, &[&base[..], args].concat())
        }

        fn new() -> Self {
            let dir = TempDir::new().expect("a temporary directory is created");
            let mbox = dir.path().join("mail.mbox");
            fs::write(&mbox, MAILBOX).expect("the fixture mailbox is written");
            Self { dir, mbox }
        }
    }

    fn run(colors: Colors, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_mboxturbo"))
            .args(args)
            .env_remove("NO_COLOR")
            .env_remove("CLICOLOR")
            .env_remove("CLICOLOR_FORCE")
            .envs(colors.no_color.map(|value| ("NO_COLOR", value)))
            .envs(colors.clicolor_force.map(|value| ("CLICOLOR_FORCE", value)))
            .output()
            .expect("the built mboxturbo binary runs")
    }

    fn stderr(output: &Output) -> String {
        String::from_utf8_lossy(&output.stderr).into_owned()
    }

    fn has_escape(bytes: &[u8]) -> bool {
        bytes.contains(&ESCAPE)
    }

    /// The `--json` events with the run-dependent `elapsed_ms` removed.
    fn events(output: &Output) -> Vec<Value> {
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|line| {
                let mut event: Value = serde_json::from_str(line).expect("each line is JSON");
                if let Some(object) = event.as_object_mut() {
                    object.retain(|key, _| !VOLATILE.contains(&key.as_str()));
                }
                event
            })
            .collect()
    }

    #[test]
    fn piped_stderr_has_no_escape_code_for_export_help_and_usage_errors() {
        let fixture = Fixture::new();
        for colors in [UNSET, NO_COLOR, FORCE_ZERO] {
            let export = fixture.export(colors, "out.csv", &["--overwrite"]);
            let help = run(colors, &["export", "--help"]);
            let usage = run(colors, &["export", "--bogus"]);
            assert_eq!(export.status.code(), Some(0_i32), "export succeeds");
            assert_eq!(
                usage.status.code(),
                Some(64_i32),
                "a bad flag is a usage error"
            );
            assert!(
                !has_escape(&export.stderr) && !has_escape(&usage.stderr),
                "a piped export and a usage error carry no ESC byte"
            );
            assert!(
                !has_escape(&help.stderr) && !has_escape(&help.stdout),
                "--help carries no ESC byte"
            );
        }
    }

    #[test]
    fn forced_styling_reaches_clap_and_the_bar_line() {
        let fixture = Fixture::new();
        let export = fixture.export(FORCE_ONE, "out.csv", &[]);
        let help = run(FORCE_ONE, &["export", "--help"]);
        assert!(
            has_escape(&export.stderr),
            "a styled export clears its bar line with an escape code"
        );
        assert!(
            has_escape(&help.stdout),
            "clap is given ColorChoice::Always"
        );
    }

    #[test]
    fn no_color_beats_forced_styling() {
        let fixture = Fixture::new();
        let colors = Colors {
            clicolor_force: Some("1"),
            no_color: Some("1"),
        };
        let export = fixture.export(colors, "out.csv", &[]);
        assert!(
            !has_escape(&export.stderr),
            "NO_COLOR wins over CLICOLOR_FORCE"
        );
    }

    #[test]
    fn the_first_export_prints_the_rebuild_note_and_the_summary_line() {
        let fixture = Fixture::new();
        let output = fixture.export(UNSET, "out.csv", &[]);
        let text = stderr(&output);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines.first(),
            Some(&"mboxturbo: index rebuilt"),
            "the note comes first"
        );
        assert_eq!(
            lines.len(),
            2_usize,
            "the note and one summary line: {text}"
        );
        assert!(
            lines
                .get(1)
                .is_some_and(|line| line.contains("exported 4 messages")),
            "the summary line counts the messages: {text}"
        );
    }

    #[test]
    fn a_later_export_loads_the_index_and_prints_only_the_summary_line() {
        let fixture = Fixture::new();
        let first = fixture.export(UNSET, "first.csv", &[]);
        assert_eq!(
            first.status.code(),
            Some(0_i32),
            "the first export succeeds"
        );
        let output = fixture.export(UNSET, "second.csv", &[]);
        let text = stderr(&output);
        assert_eq!(
            text.lines().count(),
            1,
            "no rebuild note the second time: {text}"
        );
        assert!(
            text.contains("second.csv") && text.contains("bytes"),
            "the summary names the output path and the bytes: {text}"
        );
    }

    #[test]
    fn the_summary_names_standard_output_as_a_dash() {
        let fixture = Fixture::new();
        let mbox = fixture.mbox.to_str().expect("the fixture path is UTF-8");
        let output = run(UNSET, &["export", mbox, "--format", "csv", "-o", "-"]);
        assert!(
            stderr(&output).contains("to - in"),
            "the output path is `-`: {}",
            stderr(&output)
        );
    }

    #[test]
    fn quiet_silences_the_note_the_summary_and_the_bar() {
        let fixture = Fixture::new();
        for flag in ["--quiet", "-q"] {
            for colors in [UNSET, FORCE_ONE] {
                let output = fixture.export(colors, "out.csv", &[flag, "--overwrite"]);
                assert_eq!(output.status.code(), Some(0_i32), "export succeeds");
                assert!(output.stderr.is_empty(), "{flag} prints nothing on stderr");
            }
        }
    }

    #[test]
    fn a_json_export_leaves_stderr_empty_even_when_styling_is_forced() {
        let fixture = Fixture::new();
        for colors in [UNSET, FORCE_ONE] {
            let output = fixture.export(colors, "out.csv", &["--json", "--overwrite"]);
            assert_eq!(output.status.code(), Some(0_i32), "the export succeeds");
            assert!(
                output.stderr.is_empty(),
                "--json prints no bar, note or summary line: {}",
                stderr(&output)
            );
        }
    }

    #[test]
    fn quiet_still_prints_error_lines() {
        let fixture = Fixture::new();
        let output = fixture.export(UNSET, "out.csv", &["--quiet", "--columns", "bogus_column"]);
        assert_eq!(
            output.status.code(),
            Some(64_i32),
            "an unknown column is a usage error"
        );
        assert_eq!(
            stderr(&output).lines().count(),
            1,
            "the error line still prints"
        );
    }

    #[test]
    fn the_json_stream_is_the_same_plain_quiet_or_styled() {
        let fixture = Fixture::new();
        let plain = fixture.export(UNSET, "plain.csv", &["--json"]);
        let quiet = fixture.export(UNSET, "quiet.csv", &["--json", "--quiet"]);
        let styled = fixture.export(FORCE_ONE, "styled.csv", &["--json"]);
        let reference = events(&plain);
        assert_eq!(
            reference
                .iter()
                .filter_map(|event| event["event"].as_str())
                .collect::<Vec<_>>()
                .first(),
            Some(&"start"),
            "the stream opens with a start event"
        );
        assert_eq!(
            events(&quiet).len(),
            reference.len(),
            "--quiet leaves the event count alone"
        );
        assert_eq!(
            events(&styled).len(),
            reference.len(),
            "styling leaves the events alone"
        );
    }
}
