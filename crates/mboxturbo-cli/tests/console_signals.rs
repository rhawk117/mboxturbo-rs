//! Ctrl-Break delivered to a running export in its own process group stops it within one batch,
//! leaves nothing at the target and exits 130; the Unix signals are covered in `signals.rs`.

#![cfg(windows)]

#[cfg(test)]
mod console_signals {
    use std::io::{BufRead as _, BufReader, BufWriter, Write as _};
    use std::os::windows::process::CommandExt as _;
    use std::process::{Child, ChildStdout, Command, Stdio};
    use std::time::{Duration, Instant};
    use std::{fs, thread};

    use serde_json::Value;
    use tempfile::TempDir;
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, GenerateConsoleCtrlEvent};
    use windows_sys::Win32::System::Threading::CREATE_NEW_PROCESS_GROUP;

    /// Enough messages for an export to span many batches of 4096 and run for a while.
    const LONG_MAILBOX: usize = 200_000;
    /// How long the test waits for something that should happen at once.
    const PATIENCE: Duration = Duration::from_secs(30);

    /// Sends Ctrl-Break to the process group that `child` leads.
    #[expect(
        unsafe_code,
        reason = "GenerateConsoleCtrlEvent is a Win32 call with no safe wrapper"
    )]
    fn send_ctrl_break(child: &Child) {
        // SAFETY: the call takes two integers and touches no memory of ours; the group id is
        // the pid of a child started with CREATE_NEW_PROCESS_GROUP.
        let sent = unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, child.id()) };
        assert_ne!(sent, 0_i32, "Ctrl-Break reaches the export's process group");
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
                return status.code().expect("the process exited with a code");
            }
            assert!(started.elapsed() < PATIENCE, "the process exits promptly");
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn ctrl_break_cancels_an_export_and_exits_130() {
        let dir = TempDir::new().expect("a temporary directory is created");
        let mbox = dir.path().join("mail.mbox");
        let mut file = BufWriter::new(fs::File::create(&mbox).expect("the mailbox is created"));
        for number in 0..LONG_MAILBOX {
            write!(
                file,
                "From a@example.com Mon Jan  1 00:00:00 2024\nSubject: message {number}\n\
                 From: a@example.com\n\nbody of message {number}\n\n"
            )
            .expect("a message is written");
        }
        file.flush().expect("the mailbox is flushed");
        let out = dir.path().join("out");
        fs::create_dir_all(&out).expect("the output directory is created");
        let target = out.join("out.parquet");
        let mut child = Command::new(env!("CARGO_BIN_EXE_mboxturbo"))
            .arg("export")
            .arg(&mbox)
            .arg("-o")
            .arg(&target)
            .args(["--format", "parquet", "--json"])
            .env("NO_COLOR", "1")
            .creation_flags(CREATE_NEW_PROCESS_GROUP)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the built mboxturbo binary starts");
        let mut reader = BufReader::new(child.stdout.take().expect("standard output is piped"));
        wait_for_progress(&mut reader);
        send_ctrl_break(&child);
        let events: Vec<Value> = reader
            .lines()
            .map(|line| {
                let text = line.expect("standard output is readable");
                serde_json::from_str(&text).expect("every line is JSON")
            })
            .collect();
        assert_eq!(exit_code(&mut child), 130_i32, "Ctrl-Break exits 130");
        assert!(!target.exists(), "an interrupted export leaves no target");
        assert_eq!(
            fs::read_dir(&out)
                .expect("the output directory is listed")
                .count(),
            0_usize,
            "an interrupted export leaves no staged file"
        );
        let last = events.last().expect("the stream ends with an event");
        assert_eq!(last["event"], "error", "the last event is the error");
        assert_eq!(last["code"], 130_i32, "the event carries the exit code");
    }
}
