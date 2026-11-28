//! A termination signal stops a running export within one batch, leaves nothing at the target and
//! exits with the signal's code; a closed stream is an I/O failure, never an interruption.

#![cfg(unix)]

#[cfg(test)]
mod signals {
    use std::io::{self, BufRead as _, BufReader, BufWriter, Read as _, Write as _};
    use std::path::{Path, PathBuf};
    use std::process::{Child, ChildStdout, Command, Stdio};
    use std::time::{Duration, Instant};
    use std::{fs, thread};

    use serde_json::Value;
    use tempfile::TempDir;

    /// Enough messages for an export to span many batches of 4096 and run for a while.
    const LONG_MAILBOX: usize = 200_000;
    /// Enough csv text that standard output fills the pipe buffer when nobody reads it.
    const WIDE_MAILBOX: usize = 20_000;
    /// Long enough for the CLI's signal watcher, which polls every 20 ms, to cancel the run.
    const SETTLE: Duration = Duration::from_millis(250);
    /// How long the tests wait for something that should happen at once.
    const PATIENCE: Duration = Duration::from_secs(30);

    /// A mailbox and an empty directory for the output, in one temporary directory.
    struct Fixture {
        dir: TempDir,
        mbox: PathBuf,
    }

    impl Fixture {
        fn new(messages: usize) -> Self {
            let dir = TempDir::new().expect("a temporary directory is created");
            let mbox = dir.path().join("mail.mbox");
            let mut file = BufWriter::new(fs::File::create(&mbox).expect("the mailbox is created"));
            for number in 0..messages {
                write!(
                    file,
                    "From a@example.com Mon Jan  1 00:00:00 2024\nSubject: message {number}\n\
                     From: a@example.com\n\nbody of message {number}\n\n"
                )
                .expect("a message is written");
            }
            file.flush().expect("the mailbox is flushed");
            fs::create_dir_all(dir.path().join("out")).expect("the output directory is created");
            Self { dir, mbox }
        }

        /// The directory that holds the output and nothing else.
        fn out_dir(&self) -> PathBuf {
            self.dir.path().join("out")
        }

        /// Spawns `mboxturbo export <mailbox> -o <target> <args>` with standard output piped.
        fn spawn(&self, args: &[&str]) -> Child {
            let mbox = self.mbox.to_str().expect("the fixture path is UTF-8");
            Command::new(env!("CARGO_BIN_EXE_mboxturbo"))
                .args(["export", mbox])
                .args(args)
                .env("NO_COLOR", "1")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("the built mboxturbo binary starts")
        }

        /// The path the export writes, which does not exist before it runs.
        fn target(&self) -> PathBuf {
            self.out_dir().join("out.parquet")
        }
    }

    /// A `--json` parquet export that reads `flag` from a FIFO, with `extra` arguments.
    struct FifoRun {
        child: Child,
        events: BufReader<ChildStdout>,
        fifo: PathBuf,
    }

    impl FifoRun {
        /// Sends `signal` once the CLI has the FIFO open, then writes `contents` to it.
        fn signal_then_write(&self, signal: &str, contents: &str) {
            let mut writer = fs::OpenOptions::new()
                .write(true)
                .open(&self.fifo)
                .expect("the FIFO is opened once the CLI reads it");
            send(&self.child, signal);
            thread::sleep(SETTLE);
            writer
                .write_all(contents.as_bytes())
                .expect("the FIFO takes the text");
        }

        /// Starts the export; it blocks reading the FIFO.
        fn start(fixture: &Fixture, flag: &str, extra: &[&str]) -> Self {
            let fifo = fixture.dir.path().join("fifo");
            let made = Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .expect("the mkfifo command runs so the test can control when the CLI reads");
            assert!(made.success(), "the FIFO is created");
            let target = fixture.target();
            let target_text = target.to_str().expect("the fixture path is UTF-8");
            let fifo_text = fifo.to_str().expect("the fixture path is UTF-8");
            let mut args = vec![
                flag,
                fifo_text,
                "-o",
                target_text,
                "--format",
                "parquet",
                "--json",
            ];
            args.extend_from_slice(extra);
            let mut child = fixture.spawn(&args);
            let events = BufReader::new(child.stdout.take().expect("standard output is piped"));
            Self {
                child,
                events,
                fifo,
            }
        }
    }

    /// Sends `signal` (a `kill -s` name) to `child`.
    fn send(child: &Child, signal: &str) {
        let status = Command::new("kill")
            .args(["-s", signal, &child.id().to_string()])
            .status()
            .expect("the kill command runs");
        assert!(status.success(), "kill -s {signal} reaches the export");
    }

    /// Parses the remaining lines of `lines` as events.
    fn events(lines: impl Iterator<Item = io::Result<String>>) -> Vec<Value> {
        lines
            .map(|line| {
                let text = line.expect("standard output is readable");
                serde_json::from_str(&text).expect("every line is JSON")
            })
            .collect()
    }

    /// Reads events until the first `progress`, so the export is known to be mid-run.
    fn wait_for_progress(reader: &mut BufReader<ChildStdout>) {
        let mut line = String::new();
        loop {
            line.clear();
            let read = reader.read_line(&mut line).expect("an event is read");
            assert_ne!(read, 0, "the export ran long enough to report progress");
            let event: Value = serde_json::from_str(&line).expect("every line is JSON");
            if event["event"] == "progress" {
                return;
            }
        }
    }

    /// Waits for `child` to exit and returns its exit code.
    fn exit_code(child: &mut Child) -> i32 {
        let started = Instant::now();
        loop {
            if let Some(status) = child.try_wait().expect("the child is waited on") {
                return status
                    .code()
                    .expect("the process exited, not died by signal");
            }
            assert!(started.elapsed() < PATIENCE, "the process exits promptly");
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Whether `dir` holds no file at all, staged or committed.
    fn is_empty(dir: &Path) -> bool {
        fs::read_dir(dir)
            .expect("the output directory is listed")
            .next()
            .is_none()
    }

    /// Waits until the export has staged a file in `dir`.
    fn wait_until_staged(dir: &Path) {
        let started = Instant::now();
        while is_empty(dir) {
            assert!(started.elapsed() < PATIENCE, "the export stages its output");
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// Everything `child` writes to standard error, read to its end.
    fn read_stderr(child: &mut Child) -> String {
        let mut text = String::new();
        let read = child
            .stderr
            .take()
            .expect("standard error is piped")
            .read_to_string(&mut text)
            .expect("standard error is read");
        assert_ne!(read, 0, "the interruption is reported on standard error");
        text
    }

    /// Checks that the last event is the error naming the interruption and the exit code.
    fn assert_interrupted(events: &[Value], expected: i32) {
        let last = events.last().expect("the stream ends with an event");
        assert_eq!(last["event"], "error", "the last event is the error");
        assert_eq!(last["code"], expected, "the event carries the exit code");
        let message = last["message"].as_str().expect("the error has a message");
        assert!(
            message.contains("interrupted"),
            "the message names the interruption"
        );
        assert!(
            message.contains("cancelled after"),
            "the message says how far the export got"
        );
    }

    /// Interrupts a `--json` export with `signal` once it reports progress, and checks that it
    /// exits with `expected`, leaves no file and ends on the error event.
    fn interrupt_json_export(signal: &str, expected: i32) {
        let fixture = Fixture::new(LONG_MAILBOX);
        let target = fixture.target();
        let mut child = fixture.spawn(&[
            "-o",
            target.to_str().expect("the fixture path is UTF-8"),
            "--format",
            "parquet",
            "--json",
        ]);
        let mut reader = BufReader::new(child.stdout.take().expect("standard output is piped"));
        wait_for_progress(&mut reader);
        send(&child, signal);
        let events = events(reader.lines());
        assert_eq!(
            exit_code(&mut child),
            expected,
            "{signal} exits with its code"
        );
        assert!(!target.exists(), "an interrupted export leaves no target");
        assert!(
            is_empty(&fixture.out_dir()),
            "an interrupted export leaves no staged file"
        );
        assert_interrupted(&events, expected);
    }

    #[test]
    fn sigint_cancels_an_export_and_exits_130() {
        interrupt_json_export("INT", 130);
    }

    #[test]
    fn sigterm_cancels_an_export_and_exits_143() {
        interrupt_json_export("TERM", 143);
    }

    #[test]
    fn sighup_cancels_an_export_and_exits_129() {
        interrupt_json_export("HUP", 129);
    }

    #[test]
    fn a_text_run_prints_one_interrupted_line_and_leaves_nothing() {
        let fixture = Fixture::new(LONG_MAILBOX);
        let target = fixture.target();
        let mut child = fixture.spawn(&[
            "-o",
            target.to_str().expect("the fixture path is UTF-8"),
            "--format",
            "parquet",
            "--quiet",
        ]);
        wait_until_staged(&fixture.out_dir());
        send(&child, "INT");
        let stderr = read_stderr(&mut child);
        assert_eq!(exit_code(&mut child), 130_i32, "SIGINT exits 130");
        assert_eq!(
            stderr.lines().count(),
            1_usize,
            "one line says the export stopped"
        );
        assert!(
            stderr.contains("interrupted"),
            "the line says the export was interrupted"
        );
        assert!(
            is_empty(&fixture.out_dir()),
            "nothing is left at or beside the target"
        );
    }

    #[test]
    fn a_second_signal_ends_a_stuck_export_at_once() {
        let fixture = Fixture::new(WIDE_MAILBOX);
        let mut child = fixture.spawn(&["-o", "-", "--format", "csv"]);
        let mut stdout = child.stdout.take().expect("standard output is piped");
        let mut first = [0_u8; 1];
        stdout
            .read_exact(&mut first)
            .expect("the export starts writing");
        // Nobody reads on: the pipe fills and the export blocks inside a write, so it cannot
        // notice the cancellation the first signal asks for.
        send(&child, "INT");
        thread::sleep(Duration::from_millis(500));
        assert!(
            child.try_wait().expect("the child is waited on").is_none(),
            "the first signal alone does not stop an export stuck in a write"
        );
        send(&child, "TERM");
        assert_eq!(
            exit_code(&mut child),
            143_i32,
            "the second signal exits with its own code"
        );
    }

    #[test]
    fn a_closed_stdout_mid_export_exits_74_not_130() {
        let fixture = Fixture::new(LONG_MAILBOX);
        let target = fixture.target();
        let mut child = fixture.spawn(&[
            "-o",
            target.to_str().expect("the fixture path is UTF-8"),
            "--format",
            "parquet",
            "--json",
        ]);
        let mut reader = BufReader::new(child.stdout.take().expect("standard output is piped"));
        let mut start = String::new();
        let read = reader
            .read_line(&mut start)
            .expect("the start event is read");
        assert_ne!(read, 0, "the export reports its start");
        drop(reader);
        assert_eq!(
            exit_code(&mut child),
            74_i32,
            "a closed stdout is an I/O failure, not a cancellation"
        );
        assert!(!target.exists(), "the failed export leaves no target");
    }

    #[test]
    fn an_unwritable_stderr_still_gets_the_error_event_and_exits_1() {
        let fixture = Fixture::new(1);
        let missing = fixture.dir.path().join("absent.mbox");
        let (reader, writer) = io::pipe().expect("a pipe is created");
        drop(reader);
        let output = Command::new(env!("CARGO_BIN_EXE_mboxturbo"))
            .args(["export", "--json", "--format", "csv", "-o"])
            .arg(fixture.out_dir().join("out.csv"))
            .arg(&missing)
            .stderr(writer)
            .output()
            .expect("the built mboxturbo binary runs");
        assert_eq!(
            output.status.code(),
            Some(1_i32),
            "an unwritable stderr exits 1"
        );
        let text = String::from_utf8(output.stdout).expect("standard output is UTF-8");
        let last: Value = serde_json::from_str(text.lines().last().expect("an event is written"))
            .expect("the last line is JSON");
        assert_eq!(last["event"], "error", "the error event is still written");
        assert_eq!(last["code"], 1_i32, "the event carries the exit code");
    }

    /// Interrupts a run that is still reading `flag` from a FIFO, and checks that it exits with
    /// `expected`, writes nothing and ends on the error event.
    fn interrupt_before_the_scan(flag: &str, extra: &[&str], signal: &str, contents: &str) {
        let expected = if signal == "TERM" { 143_i32 } else { 130_i32 };
        let fixture = Fixture::new(LONG_MAILBOX);
        let mut run = FifoRun::start(&fixture, flag, extra);
        run.signal_then_write(signal, contents);
        let events = events(run.events.lines());
        assert_eq!(
            exit_code(&mut run.child),
            expected,
            "{signal} before the export exits with its code"
        );
        assert!(
            !fixture.target().exists(),
            "an interrupted run leaves no target"
        );
        assert!(
            is_empty(&fixture.out_dir()),
            "an interrupted run leaves no staged file"
        );
        assert_interrupted(&events, expected);
    }

    #[test]
    fn sigterm_while_the_where_file_is_read_exits_143() {
        let predicate = r#"{"op":"contains","header":"subject","value":"o"}"#;
        interrupt_before_the_scan("--where-file", &[], "TERM", predicate);
    }

    #[test]
    fn sigint_before_a_since_scan_exits_130() {
        interrupt_before_the_scan(
            "--select-file",
            &["--since", "2024-01-01"],
            "INT",
            "0..10\n",
        );
    }
}
