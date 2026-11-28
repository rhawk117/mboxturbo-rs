//! The `export` subcommand: opens a mailbox and writes the selected messages in one format.

use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use std::{fs, io};

use clap::{Args, ValueEnum};
use mboxturbo::{
    CancelToken, Column, Compression, CsvExporter, DateBounds, Destination, DestinationKind,
    EmlExporter, Export, ExportSummary, Exporter, Filter, FormulaEscaping, IndexOrigin,
    IpcExporter, JsonlExporter, Mailbox, MboxExporter, MboxTurboError, Narrowed, Narrowing,
    Overwrite, ParquetExporter, Pipeline, Predicate, Progress,
};

use crate::events::{self, Counts, File, Report, Start, Summary, Throttle};
use crate::failure::{Failure, signal_failure, stderr_failure, stdout_failure};
use crate::open::open;
use crate::progress::{self, Bar, Feedback};
use crate::signals::Interrupts;
use crate::{dates, select};

/// Messages per batch: the unit the pipeline extracts and a sink writes at a time.
const BATCH_SIZE: usize = 4096;
/// The `--output` value that means standard output.
const STDOUT: &str = "-";

/// The arguments of `mboxturbo export`.
#[derive(Debug, Args)]
pub(crate) struct ExportArgs {
    /// Columns to write, comma-separated; `header:<Name>` selects any header [default: every
    /// column that needs no body parsing].
    #[arg(long, value_delimiter = ',', value_name = "NAME,...")]
    columns: Option<Vec<String>>,
    /// The output format.
    #[arg(long, value_enum)]
    format: Format,
    /// Keep the message index in this file instead of beside the mailbox.
    #[arg(long, value_name = "PATH")]
    index: Option<PathBuf>,
    /// The filters that narrow the export.
    #[command(flatten)]
    limits: Box<Limits>,
    /// The mbox file to export.
    mailbox: PathBuf,
    /// Where to write: a file, a directory for eml, or `-` for standard output.
    #[arg(short, long, value_name = "OUT")]
    output: PathBuf,
    /// Replace the output if it already exists.
    #[arg(long)]
    overwrite: bool,
    /// Messages to export: a 0-based position `N` or a half-open range `A..B`, comma-separated;
    /// repeatable [default: every message].
    #[arg(long, value_name = "SPEC")]
    select: Vec<String>,
    /// A file of selections, one SPEC per line; blank lines are ignored.
    #[arg(long, value_name = "FILE")]
    select_file: Option<PathBuf>,
}

/// The filters of `export` that decide by what a message holds rather than where it is.
#[derive(Debug, Args)]
struct Limits {
    /// Keep only messages dated at or after this moment: an RFC 3339 timestamp with an offset or
    /// a date `YYYY-MM-DD` (midnight UTC). Messages with no date are excluded.
    #[arg(long, value_name = "WHEN")]
    since: Option<Box<str>>,
    /// Keep only messages dated before this moment, in the same forms as `--since`. Messages
    /// with no date are excluded.
    #[arg(long, value_name = "WHEN")]
    until: Option<Box<str>>,
    /// A file holding the predicate in its JSON form, as for `--where`.
    #[arg(long, value_name = "PATH")]
    where_file: Option<PathBuf>,
    /// Keep only messages matching this predicate, given in its JSON form such as
    /// `{"op":"contains","header":"subject","value":"invoice"}`.
    #[arg(long = "where", value_name = "JSON", conflicts_with = "where_file")]
    where_json: Option<String>,
}

impl ExportArgs {
    /// The library policy for an output that already exists.
    const fn overwrite_policy(&self) -> Overwrite {
        if self.overwrite {
            Overwrite::Replace
        } else {
            Overwrite::Refuse
        }
    }
}

/// The output formats.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum Format {
    /// An Arrow IPC stream.
    Arrow,
    /// Comma-separated values.
    Csv,
    /// One `.eml` file per message in a directory.
    Eml,
    /// One JSON object per line.
    Jsonl,
    /// A single mbox file.
    Mbox,
    /// A Parquet file.
    Parquet,
}

impl Format {
    /// The sink that writes this format for a mailbox of `messages` messages.
    fn exporter(self, messages: usize) -> Box<dyn Exporter> {
        match self {
            Self::Arrow => Box::new(IpcExporter::new()),
            Self::Csv => Box::new(CsvExporter::new(FormulaEscaping::default())),
            Self::Eml => Box::new(EmlExporter::new(messages)),
            Self::Jsonl => Box::new(JsonlExporter::new()),
            Self::Mbox => Box::new(MboxExporter::new()),
            Self::Parquet => Box::new(ParquetExporter::new(Compression::default())),
        }
    }

    /// The name the format has on the command line and in events.
    const fn name(self) -> &'static str {
        match self {
            Self::Arrow => "arrow",
            Self::Csv => "csv",
            Self::Eml => "eml",
            Self::Jsonl => "jsonl",
            Self::Mbox => "mbox",
            Self::Parquet => "parquet",
        }
    }
}

/// What limits an export beyond the whole mailbox, parsed before the mailbox is opened.
struct Restrictions {
    /// The `--since` and `--until` bounds.
    bounds: DateBounds,
    /// The `--where` or `--where-file` filter.
    filter: Option<Filter>,
    /// The `--select` ranges.
    ranges: Vec<Range<usize>>,
}

/// What one export reports besides the library's own progress and summary, and how.
struct Reported<'run> {
    /// The command line.
    args: &'run ExportArgs,
    /// How many messages the selection holds.
    count: usize,
    /// How much is said on standard error.
    feedback: Feedback,
    /// How the mailbox's index was obtained.
    origin: IndexOrigin,
    /// Whether standard output carries events or text.
    report: Report,
    /// How many undated messages the date bounds excluded; `None` when no bound was given.
    undated: Option<usize>,
    /// The cancellation shared with the export and the signal handlers.
    watch: &'run Watch,
}

/// The token a signal cancels and the handlers that cancel it, installed before the first scan.
struct Watch {
    /// Cancelled by a signal, and by the observer when an event cannot be written.
    cancel: CancelToken,
    /// The signal handlers.
    interrupts: Interrupts,
}

/// Receives the library's progress: redraws the bar and, with events, writes throttled
/// `progress` events. The first event write that fails is kept in `failure` and the export is
/// cancelled at once, so no later event is written.
struct Observer {
    /// The bar, until a write to it fails.
    bar: Option<Bar<io::Stderr>>,
    /// Cancels the export when an event cannot be written.
    cancel: CancelToken,
    /// The first event write that failed.
    failure: Arc<OnceLock<io::Error>>,
    /// Admits at most one event per interval; `None` without events.
    throttle: Option<Throttle>,
}

impl Observer {
    /// Draws the bar for `counts`; a bar that cannot be written to is dropped, since standard
    /// error has nowhere left to report that.
    fn draw(&mut self, counts: Counts, now: Instant) {
        if let Some(bar) = &mut self.bar
            && bar.update(counts, now).is_err()
        {
            self.bar = None;
        }
    }

    /// Writes a `progress` event for `counts` when the throttle admits one.
    fn emit(&mut self, counts: Counts, now: Instant) {
        let Some(throttle) = &mut self.throttle else {
            return;
        };
        if !throttle.admit(now) {
            return;
        }
        if let Err(error) = events::progress(counts)
            && self.failure.set(error).is_ok()
        {
            self.cancel.cancel();
        }
    }

    /// An observer for the run described by `reported`.
    fn new(
        reported: &Reported<'_>,
        failure: Arc<OnceLock<io::Error>>,
        cancel: CancelToken,
    ) -> Self {
        let now = Instant::now();
        Self {
            bar: reported
                .feedback
                .draws()
                .then(|| Bar::new(io::stderr(), now)),
            cancel,
            failure,
            throttle: (reported.report == Report::Events)
                .then(|| Throttle::new(events::PROGRESS_INTERVAL)),
        }
    }

    /// Handles one library progress report.
    fn observe(&mut self, progress: Progress) {
        let now = Instant::now();
        let counts = Counts::from(progress);
        self.draw(counts, now);
        self.emit(counts, now);
    }
}

/// Runs the `export` subcommand, reporting it as events when `report` asks for them.
///
/// # Errors
///
/// A [`Failure::Usage`] for an unknown column, a malformed or out-of-range selection, standard
/// output with a format that cannot stream, or `--json` with standard output, all found before
/// anything is written; a [`Failure::Core`] for everything the library refuses, including a
/// predicate that is not valid, and for an event that cannot be written to standard output.
///
/// The signal handlers are installed before anything is read or scanned, so a signal that
/// arrives during the predicate scan or the date scan cancels it and is reported as
/// [`Failure::Interrupted`], naming the `-o` target, with nothing written.
pub(crate) fn run(args: &ExportArgs, report: Report, feedback: Feedback) -> Result<(), Failure> {
    refuse_events_on_stdout(args, report)?;
    let cancel = CancelToken::new();
    let interrupts = Interrupts::watch(cancel.clone()).map_err(signal_failure)?;
    let watch = Watch { cancel, interrupts };
    let columns = columns(args.format, args.columns.as_deref())?;
    let destination = destination(args.format, &args.output)?;
    let restrictions = restrictions(args)?;
    let mailbox = Arc::new(open(&args.mailbox, args.index.as_deref())?);
    let selected = kept(args, restrictions, &mailbox, &watch)?;
    let pipeline = Arc::new(Pipeline::new(columns, BATCH_SIZE));
    let exporter = args.format.exporter(mailbox.len());
    let origin = mailbox.index_origin();
    let export = Export::new(pipeline, mailbox, destination)
        .cancel_token(watch.cancel.clone())
        .selection(selected.selection)
        .overwrite(args.overwrite_policy());
    let reported = Reported {
        args,
        count: selected.count,
        feedback,
        origin,
        report,
        undated: selected.excluded_undated,
        watch: &watch,
    };
    progress::note_origin(feedback, origin).map_err(stderr_failure)?;
    run_export(export, exporter, &reported)
}

/// Parses `--select`, `--since`, `--until` and the predicate, all before the mailbox is opened
/// so a bad one costs no scan.
fn restrictions(args: &ExportArgs) -> Result<Restrictions, Failure> {
    Ok(Restrictions {
        ranges: select::parse_all(&args.select)?,
        bounds: dates::bounds(args.limits.since.as_deref(), args.limits.until.as_deref())?,
        filter: filter(args)?,
    })
}

/// Standard output carries the events, so it cannot also carry the data.
fn refuse_events_on_stdout(args: &ExportArgs, report: Report) -> Result<(), Failure> {
    if report == Report::Events && args.output.as_os_str() == STDOUT {
        return Err(Failure::Usage(
            "--json cannot be used with `-o -`: standard output carries the events".to_owned(),
        ));
    }
    Ok(())
}

/// Runs `export`, drawing the bar and writing the events its `reported` mode asks for: with
/// events, `start`, `index`, throttled `progress`, a last `progress`, `file` and `summary`; then
/// the summary line on standard error.
///
/// A failed event write cancels the export and is reported as an I/O failure once it has stopped.
/// A termination signal cancels it too and is reported as [`Failure::Interrupted`].
fn run_export(
    export: Export,
    exporter: Box<dyn Exporter>,
    reported: &Reported<'_>,
) -> Result<(), Failure> {
    if reported.report == Report::Events {
        write_start(reported).map_err(stdout_failure)?;
    }
    let failure = Arc::new(OnceLock::new());
    let mut observer = Observer::new(
        reported,
        Arc::clone(&failure),
        reported.watch.cancel.clone(),
    );
    let result = export
        .on_progress(move |progress| observer.observe(progress))
        .run(exporter);
    if reported.feedback.draws() {
        Bar::new(io::stderr(), Instant::now())
            .clear()
            .map_err(stderr_failure)?;
    }
    if let Some(source) = failure.get() {
        return Err(stdout_failure(io::Error::new(
            source.kind(),
            source.to_string(),
        )));
    }
    let summary = result.map_err(|error| core_failure(error, &reported.watch.interrupts))?;
    finish(reported, &summary)
}

/// Writes the `start` and `index` events.
fn write_start(reported: &Reported<'_>) -> io::Result<()> {
    events::start(&Start {
        command: "export",
        format: reported.args.format.name(),
        mailbox: &reported.args.mailbox,
        output: &reported.args.output,
        selected: reported.count,
    })?;
    events::index(reported.origin)
}

/// The failure for a library `error` after the mailbox is open: an interruption when it is a
/// cancellation and a signal has arrived, otherwise an ordinary core failure.
fn core_failure(error: MboxTurboError, interrupts: &Interrupts) -> Failure {
    let signalled = interrupts
        .code()
        .filter(|_| matches!(error, MboxTurboError::Cancelled { .. }));
    match signalled {
        Some(code) => Failure::Interrupted {
            error: Box::new(error),
            code,
        },
        None => Failure::other(Box::new(error)),
    }
}

/// Finishes a successful export: the events when asked for, then the summary line.
fn finish(reported: &Reported<'_>, summary: &ExportSummary) -> Result<(), Failure> {
    // Standard output is refused for `--json`, so an event run always committed a path; a text
    // run to standard output names it `-`.
    let path = summary.path.as_deref().unwrap_or(&reported.args.output);
    if reported.report == Report::Events {
        finish_events(reported, summary, path).map_err(stdout_failure)?;
    }
    progress::print_summary(reported.feedback, summary, path, reported.undated)
        .map_err(stderr_failure)
}

/// Writes the events that follow a finished export: the last `progress`, `file` and `summary`.
fn finish_events(reported: &Reported<'_>, summary: &ExportSummary, path: &Path) -> io::Result<()> {
    events::progress(Counts {
        bytes: summary.bytes,
        messages: summary.messages,
        total: summary.messages,
    })?;
    events::file(&File {
        bytes: summary.bytes,
        format: reported.args.format.name(),
        messages: summary.messages,
        path,
    })?;
    events::summary(&Summary {
        bytes: summary.bytes,
        elapsed: summary.elapsed,
        messages: summary.messages,
        path,
        excluded_undated: reported.undated,
    })
}

/// The columns to extract: a fixed set for the formats that write whole messages, otherwise the
/// requested columns by name, or the library defaults when none are named.
fn columns(format: Format, requested: Option<&[String]>) -> Result<Vec<Column>, Failure> {
    let whole = match format {
        Format::Eml => Some(vec![
            Column::Raw,
            Column::Position,
            Column::MessageId,
            Column::Date,
        ]),
        Format::Mbox => Some(vec![Column::Raw, Column::Position]),
        Format::Arrow | Format::Csv | Format::Jsonl | Format::Parquet => None,
    };
    if let Some(fixed) = whole {
        if requested.is_some() {
            return Err(Failure::Usage(format!(
                "--columns cannot be used with {}, which writes whole messages",
                format.name()
            )));
        }
        return Ok(fixed);
    }
    let Some(names) = requested else {
        return Ok(Column::defaults());
    };
    names
        .iter()
        .map(|name| {
            Column::from_name(name)
                .ok_or_else(|| Failure::Usage(format!("unknown column `{name}`")))
        })
        .collect()
}

/// Where the output goes: standard output for `-`, otherwise a directory for eml and a file for
/// the rest.
fn destination(format: Format, output: &Path) -> Result<Destination, Failure> {
    if output.as_os_str() != STDOUT {
        return Ok(match format {
            Format::Eml => Destination::Directory(output.to_path_buf()),
            Format::Arrow | Format::Csv | Format::Jsonl | Format::Mbox | Format::Parquet => {
                Destination::File(output.to_path_buf())
            },
        });
    }
    if format.exporter(0).accepts(DestinationKind::Stream) {
        return Ok(Destination::Stream(Box::new(io::stdout())));
    }
    Err(Failure::Usage(format!(
        "{} output cannot be written to standard output, so `-o -` is not allowed",
        format.name()
    )))
}

/// The messages to export: those `args` select by position, or every message, that also fall
/// inside the bounds and satisfy the filter of `restrictions`.
///
/// Positions come out ascending and without repeats whatever order `--select` lists them in, so
/// the export keeps mailbox order.
fn kept(
    args: &ExportArgs,
    restrictions: Restrictions,
    mailbox: &Mailbox,
    watch: &Watch,
) -> Result<Narrowed, Failure> {
    let bounds = restrictions.bounds;
    let mut narrowing = Narrowing::new();
    if !bounds.is_unbounded() {
        narrowing = narrowing.dates(bounds);
    }
    if let Some(positions) = chosen_positions(args, restrictions.ranges, mailbox)? {
        narrowing = narrowing.positions(positions);
    }
    if let Some(filter) = &restrictions.filter {
        narrowing = narrowing.filter(filter);
    }
    narrowing
        .select(mailbox, Some(&watch.cancel))
        .map_err(|error| scan_failure(error, args, watch))
}

/// The failure for an `error` from the scan: a cancellation names the `-o` target, or a stream
/// for `-o -`, since the scan itself knows no target.
fn scan_failure(error: MboxTurboError, args: &ExportArgs, watch: &Watch) -> Failure {
    let named = if let MboxTurboError::Cancelled { written, .. } = error {
        MboxTurboError::Cancelled {
            target: (args.output.as_os_str() != STDOUT).then(|| args.output.clone()),
            written,
        }
    } else {
        error
    };
    core_failure(named, &watch.interrupts)
}

/// The filter that `--where` or `--where-file` asks for; `None` when the command line has
/// neither flag.
///
/// The predicate is checked here, before the mailbox is opened, so a bad one costs no scan.
fn filter(args: &ExportArgs) -> Result<Option<Filter>, Failure> {
    let text = match (&args.limits.where_json, &args.limits.where_file) {
        (Some(json), _) => json.clone(),
        (None, Some(path)) => fs::read_to_string(path).map_err(|source| {
            Failure::other(Box::new(MboxTurboError::Io {
                path: path.clone(),
                source,
            }))
        })?,
        (None, None) => return Ok(None),
    };
    let predicate = Predicate::from_json(&text).map_err(|error| Failure::other(Box::new(error)))?;
    Filter::new(&predicate)
        .map(Some)
        .map_err(|error| Failure::other(Box::new(error)))
}

/// The ascending positions named by `ranges` (from `--select`) united with the `--select-file`
/// lines; `None` when neither is given.
fn chosen_positions(
    args: &ExportArgs,
    mut ranges: Vec<Range<usize>>,
    mailbox: &Mailbox,
) -> Result<Option<Vec<usize>>, Failure> {
    if args.select.is_empty() && args.select_file.is_none() {
        return Ok(None);
    }
    if let Some(path) = &args.select_file {
        ranges.extend(select_file(path)?);
        if ranges.is_empty() {
            return Err(Failure::Usage(format!(
                "{} selects no messages",
                path.display()
            )));
        }
    }
    Ok(Some(select::positions(ranges, mailbox.len())?))
}

/// The ranges named by the lines of the file at `path`; blank lines are ignored.
fn select_file(path: &Path) -> Result<Vec<Range<usize>>, Failure> {
    let text = fs::read_to_string(path).map_err(|source| {
        Failure::other(Box::new(MboxTurboError::Io {
            path: path.to_path_buf(),
            source,
        }))
    })?;
    let lines: Vec<String> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::to_owned)
        .collect();
    Ok(select::parse_all(&lines)?)
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    /// Just enough of the command line to parse the export arguments.
    #[derive(Debug, Parser)]
    struct Line {
        /// The arguments under test.
        #[command(flatten)]
        args: ExportArgs,
    }

    /// What `scan_failure` gives a cancelled scan of an export written to `output`.
    fn cancelled_failure(output: &str) -> Failure {
        let line = Line::try_parse_from(["export", "mail.mbox", "--format", "csv", "-o", output])
            .expect("the export arguments parse");
        let cancel = CancelToken::new();
        let interrupts = Interrupts::watch(cancel.clone()).expect("the signal handlers install");
        let watch = Watch { cancel, interrupts };
        let error = MboxTurboError::Cancelled {
            target: None,
            written: 0,
        };
        scan_failure(error, &line.args, &watch)
    }

    #[test]
    fn a_cancelled_scan_names_the_output_path() {
        let failure = cancelled_failure("out/mail.csv");
        let Failure::Core { error, .. } = failure else {
            panic!("a cancelled scan is a library failure, got {failure:?}");
        };
        assert!(
            matches!(
                &*error,
                MboxTurboError::Cancelled { target: Some(target), .. }
                    if target == Path::new("out/mail.csv")
            ),
            "the error names the -o target, got: {error:?}"
        );
    }

    #[test]
    fn a_cancelled_scan_names_a_stream_for_dash() {
        let failure = cancelled_failure("-");
        let Failure::Core { error, .. } = failure else {
            panic!("a cancelled scan is a library failure, got {failure:?}");
        };
        assert!(
            matches!(&*error, MboxTurboError::Cancelled { target: None, .. }),
            "the error names no target for -o -, got: {error:?}"
        );
    }
}
