//! `mboxturbo show` writes one message's stored bytes and `mboxturbo info` reports a mailbox's
//! count and date span, each from the index, with the exit codes of `export`.

#[cfg(test)]
mod show_info {
    use std::fs;
    #[cfg(target_os = "linux")]
    use std::fs::OpenOptions;
    use std::path::PathBuf;
    #[cfg(target_os = "linux")]
    use std::process::Stdio;
    use std::process::{Command, Output};

    use tempfile::TempDir;

    /// Four messages: dated 2024-03-05 12:30:15, undated, dated 2024-01-01, and undated.
    const MESSAGES: [&str; 4] = [
        concat!(
            "From a@example.com Mon Jan  1 00:00:00 2024\nSubject: zero\n",
            "Date: Tue, 5 Mar 2024 12:30:15 +0000\n\nbody zero\n\n"
        ),
        "From b@example.com Mon Jan  1 00:00:00 2024\nSubject: one\n\nbody one\n\n",
        concat!(
            "From c@example.com Mon Jan  1 00:00:00 2024\nSubject: two\n",
            "Date: Mon, 1 Jan 2024 00:00:00 +0000\n\nbody two\n\n"
        ),
        "From d@example.com Mon Jan  1 00:00:00 2024\nSubject: three\n\nbody three\n",
    ];

    /// A temporary directory holding a mailbox.
    struct Fixture {
        dir: TempDir,
        mbox: PathBuf,
    }

    impl Fixture {
        /// A fixture whose mailbox file holds `contents`.
        fn holding(contents: &str) -> Self {
            let dir = TempDir::new().expect("a temporary directory is created");
            let mbox = dir.path().join("mail.mbox");
            fs::write(&mbox, contents).expect("the fixture mailbox is written");
            Self { dir, mbox }
        }

        /// The string form of the mailbox path.
        fn mailbox(&self) -> &str {
            self.mbox.to_str().expect("the fixture path is UTF-8")
        }

        /// The four-message fixture mailbox.
        fn new() -> Self {
            Self::holding(&MESSAGES.concat())
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

    fn run_with(args: &[&str], no_color: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_mboxturbo"))
            .args(args)
            .env("NO_COLOR", no_color)
            .output()
            .expect("the built mboxturbo binary runs")
    }

    fn run(args: &[&str]) -> Output {
        run_with(args, "1")
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

    fn stdout(output: &Output) -> String {
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    #[test]
    fn show_writes_the_stored_bytes_of_the_first_a_middle_and_the_last_message() {
        let fixture = Fixture::new();
        for (position, stored) in MESSAGES.iter().enumerate() {
            let output = run(&["show", fixture.mailbox(), &position.to_string()]);
            assert_eq!(code(&output), 0_i32, "show {position}: {}", stderr(&output));
            assert_eq!(
                output.stdout,
                stored.as_bytes(),
                "show {position} writes the message unchanged"
            );
        }
    }

    #[test]
    fn show_past_the_end_exits_64_naming_the_position() {
        let fixture = Fixture::new();
        let output = run(&["show", fixture.mailbox(), "4711"]);
        assert_eq!(code(&output), 64_i32, "a position past the end is usage");
        assert!(
            stderr(&output).contains("4711"),
            "the error names the position: {}",
            stderr(&output)
        );
        assert!(output.stdout.is_empty(), "no message bytes are written");
    }

    #[test]
    fn show_at_the_message_count_exits_64() {
        let fixture = Fixture::new();
        let output = run(&["show", fixture.mailbox(), "4"]);
        assert_eq!(code(&output), 64_i32, "the first position past the end");
    }

    #[test]
    fn show_with_a_malformed_position_is_a_usage_error() {
        let fixture = Fixture::new();
        let output = run(&["show", fixture.mailbox(), "first"]);
        assert_eq!(code(&output), 64_i32, "a non-number position is usage");
    }

    #[test]
    fn show_of_a_missing_mailbox_exits_66() {
        let fixture = Fixture::new();
        let missing = fixture.target("absent.mbox");
        let output = run(&["show", &missing, "0"]);
        assert_eq!(code(&output), 66_i32, "{}", stderr(&output));
    }

    #[test]
    fn info_of_a_missing_mailbox_exits_66() {
        let fixture = Fixture::new();
        let missing = fixture.target("absent.mbox");
        let output = run(&["info", &missing]);
        assert_eq!(code(&output), 66_i32, "{}", stderr(&output));
    }

    #[test]
    fn info_reports_the_count_the_span_and_the_undated_messages() {
        let fixture = Fixture::new();
        let output = run(&["info", fixture.mailbox()]);
        assert_eq!(code(&output), 0_i32, "info succeeds: {}", stderr(&output));
        assert_eq!(
            stdout(&output),
            concat!(
                "messages: 4\nearliest: 2024-01-01T00:00:00Z\n",
                "latest: 2024-03-05T12:30:15Z\nundated: 2\n"
            ),
            "the count, the dated span and the undated count"
        );
    }

    #[test]
    fn info_of_an_empty_mailbox_prints_no_span() {
        let fixture = Fixture::holding("");
        let output = run(&["info", fixture.mailbox()]);
        assert_eq!(code(&output), 0_i32, "info succeeds: {}", stderr(&output));
        assert_eq!(
            stdout(&output),
            "messages: 0\nundated: 0\n",
            "an empty mailbox has no span"
        );
    }

    #[test]
    fn info_of_an_undated_mailbox_prints_no_span() {
        let fixture = Fixture::holding(MESSAGES[1]);
        let output = run(&["info", fixture.mailbox()]);
        assert_eq!(code(&output), 0_i32, "info succeeds: {}", stderr(&output));
        assert_eq!(
            stdout(&output),
            "messages: 1\nundated: 1\n",
            "an undated message gives no span"
        );
    }

    #[test]
    fn quiet_and_no_color_leave_standard_output_identical() {
        let fixture = Fixture::new();
        let mailbox = fixture.mailbox();
        for command in [vec!["show", mailbox, "1"], vec!["info", mailbox]] {
            let plain = run(&command);
            let quiet = run_with(&[command.as_slice(), &["--quiet"]].concat(), "");
            assert_eq!(
                plain.stdout, quiet.stdout,
                "{}: stdout is data, whatever the feedback options",
                command[0]
            );
        }
    }

    #[test]
    fn quiet_drops_only_the_index_rebuilt_note() {
        let fixture = Fixture::new();
        let loud_index = fixture.target("loud.idx");
        let quiet_index = fixture.target("quiet.idx");
        let loud = run(&["info", fixture.mailbox(), "--index", &loud_index]);
        let quiet = run(&[
            "info",
            fixture.mailbox(),
            "--index",
            &quiet_index,
            "--quiet",
        ]);
        assert!(
            stderr(&loud).contains("index rebuilt"),
            "a first run notes the rebuild: {}",
            stderr(&loud)
        );
        assert!(
            quiet.stderr.is_empty(),
            "--quiet leaves stderr empty: {}",
            stderr(&quiet)
        );
        assert_eq!(loud.stdout, quiet.stdout, "stdout does not change");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn show_exits_74_when_standard_output_cannot_take_the_bytes() {
        let fixture = Fixture::new();
        let full = OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .expect("/dev/full opens for writing");
        let output = Command::new(env!("CARGO_BIN_EXE_mboxturbo"))
            .args(["show", fixture.mailbox(), "0"])
            .stdout(Stdio::from(full))
            .output()
            .expect("the built mboxturbo binary runs");
        assert_eq!(
            code(&output),
            74_i32,
            "T13 FC-1: show must not exit 0 when its bytes did not reach stdout: {}",
            stderr(&output)
        );
    }
}
