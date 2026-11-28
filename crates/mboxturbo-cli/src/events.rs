//! The `--json` event stream: versioned JSON Lines on standard output.
//!
//! Every line is one JSON object with `"v": 1` and an `"event"` name; the shapes are described by
//! `schema/events-v1.json`, which ships with the crate. A run that fails before the mailbox is
//! open writes only an `error` event.

use std::io::{self, Write as _};
use std::path::Path;
use std::time::{Duration, Instant};

use mboxturbo::{IndexOrigin, Progress, rfc3339};
use serde_json::{Value, json};

/// The version carried by every event; a change to an event's shape bumps it.
const VERSION: u8 = 1;

/// The most often a progress event is written.
pub(crate) const PROGRESS_INTERVAL: Duration = Duration::from_secs(1);

/// How a command reports itself on standard output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Report {
    /// The versioned event stream, one JSON object per line.
    Events,
    /// Human text, as the command always wrote it.
    Text,
}

/// What a `progress` event reports.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Counts {
    /// Bytes written so far.
    pub bytes: u64,
    /// Messages written so far.
    pub messages: u64,
    /// Messages the selection yields in total.
    pub total: u64,
}

impl From<Progress> for Counts {
    fn from(progress: Progress) -> Self {
        Self {
            bytes: progress.bytes,
            messages: progress.messages,
            total: progress.total,
        }
    }
}

/// What an `info` event reports: the shape of one mailbox.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Info {
    /// How many messages the mailbox holds.
    pub count: usize,
    /// Unix seconds of the earliest dated message; `None` when no message has a date.
    pub earliest: Option<i64>,
    /// Unix seconds of the latest dated message; `None` when no message has a date.
    pub latest: Option<i64>,
    /// How many messages have no date.
    pub undated: usize,
}

/// What a `start` event reports.
#[derive(Debug)]
pub(crate) struct Start<'run> {
    /// The subcommand that is running.
    pub command: &'run str,
    /// The output format's name.
    pub format: &'run str,
    /// The mailbox being read.
    pub mailbox: &'run Path,
    /// The `--output` path.
    pub output: &'run Path,
    /// How many messages the selection holds.
    pub selected: usize,
}

/// What a `file` event reports: one output path.
#[derive(Debug)]
pub(crate) struct File<'run> {
    /// Bytes written to the path.
    pub bytes: u64,
    /// The output format's name.
    pub format: &'run str,
    /// Messages written to the path.
    pub messages: u64,
    /// The committed file, or the directory for eml.
    pub path: &'run Path,
}

/// What a `summary` event reports: the finished run.
#[derive(Debug)]
pub(crate) struct Summary<'run> {
    /// Bytes written.
    pub bytes: u64,
    /// Wall-clock time the export took.
    pub elapsed: Duration,
    /// The undated messages the bounds excluded from the `--select` positions, or from the whole
    /// mailbox without `--select`; `None` when no bound was given.
    pub excluded_undated: Option<usize>,
    /// Messages written.
    pub messages: u64,
    /// The committed file or directory.
    pub path: &'run Path,
}

/// Lets a progress event through at most once per interval, by the instants it is asked about.
#[derive(Debug)]
pub(crate) struct Throttle {
    /// The least time between two admitted events.
    interval: Duration,
    /// When the last event was admitted; `None` before the first.
    last: Option<Instant>,
}

impl Throttle {
    /// Whether an event at `now` is admitted; an admitted event starts a new interval.
    pub(crate) fn admit(&mut self, now: Instant) -> bool {
        let due = self
            .last
            .is_none_or(|last| now.saturating_duration_since(last) >= self.interval);
        if due {
            self.last = Some(now);
        }
        due
    }

    /// A throttle that admits the first event and then one per `interval`.
    pub(crate) const fn new(interval: Duration) -> Self {
        Self {
            interval,
            last: None,
        }
    }
}

/// Writes an `error` event: `code` is the process exit code, `message` the stderr line.
///
/// # Errors
///
/// The I/O error of writing to standard output.
pub(crate) fn error(code: u8, message: &str) -> io::Result<()> {
    emit(&json!({ "v": VERSION, "event": "error", "code": code, "message": message }))
}

/// Writes a `file` event.
///
/// # Errors
///
/// The I/O error of writing to standard output.
pub(crate) fn file(file: &File<'_>) -> io::Result<()> {
    emit(&json!({
        "v": VERSION,
        "event": "file",
        "bytes": file.bytes,
        "format": file.format,
        "messages": file.messages,
        "path": file.path.display().to_string(),
    }))
}

/// Writes an `index` event: whether opening loaded the index or rebuilt it.
///
/// # Errors
///
/// The I/O error of writing to standard output.
pub(crate) fn index(origin: IndexOrigin) -> io::Result<()> {
    let name = format!("{origin:?}").to_lowercase();
    emit(&json!({ "v": VERSION, "event": "index", "origin": name }))
}

/// Writes an `info` event.
///
/// # Errors
///
/// The I/O error of writing to standard output.
pub(crate) fn info(info: &Info) -> io::Result<()> {
    emit(&json!({
        "v": VERSION,
        "event": "info",
        "count": info.count,
        "earliest": info.earliest.map(rfc3339),
        "latest": info.latest.map(rfc3339),
        "undated": info.undated,
    }))
}

/// Writes a `progress` event.
///
/// # Errors
///
/// The I/O error of writing to standard output.
pub(crate) fn progress(counts: Counts) -> io::Result<()> {
    emit(&json!({
        "v": VERSION,
        "event": "progress",
        "bytes": counts.bytes,
        "messages": counts.messages,
        "total": counts.total,
    }))
}

/// Writes a `start` event.
///
/// # Errors
///
/// The I/O error of writing to standard output.
pub(crate) fn start(start: &Start<'_>) -> io::Result<()> {
    emit(&json!({
        "v": VERSION,
        "event": "start",
        "command": start.command,
        "format": start.format,
        "mailbox": start.mailbox.display().to_string(),
        "output": start.output.display().to_string(),
        "selected": start.selected,
    }))
}

/// Writes a `summary` event.
///
/// # Errors
///
/// The I/O error of writing to standard output.
pub(crate) fn summary(summary: &Summary<'_>) -> io::Result<()> {
    let mut event = json!({
        "v": VERSION,
        "event": "summary",
        "bytes": summary.bytes,
        "elapsed_ms": millis(summary.elapsed),
        "messages": summary.messages,
        "path": summary.path.display().to_string(),
    });
    if let (Some(count), Some(object)) = (summary.excluded_undated, event.as_object_mut()) {
        let _absent = object.insert("excluded_undated".to_owned(), json!(count));
    }
    emit(&event)
}

/// Whole milliseconds in `duration`, saturating rather than wrapping.
fn millis(duration: Duration) -> u64 {
    duration
        .as_secs()
        .saturating_mul(1000)
        .saturating_add(u64::from(duration.subsec_millis()))
}

/// Writes `event` as one line on standard output.
fn emit(event: &Value) -> io::Result<()> {
    writeln!(io::stdout().lock(), "{event}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_closer_than_the_interval_are_dropped_and_the_next_interval_admits_one() {
        let base = Instant::now();
        let at = |millis: u64| {
            base.checked_add(Duration::from_millis(millis))
                .expect("a test instant stays in range")
        };
        let mut throttle = Throttle::new(PROGRESS_INTERVAL);
        let admitted: Vec<bool> = [0, 400, 999, 1000, 1500, 2000]
            .into_iter()
            .map(|millis| throttle.admit(at(millis)))
            .collect();
        assert_eq!(
            admitted,
            [true, false, false, true, false, true],
            "at most one event per second, the first always admitted"
        );
    }
}
