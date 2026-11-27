//! The `export` subcommand: opens a mailbox and writes the selected messages in one format.

use std::error::Error as _;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use std::{fmt, fs, io};

use clap::{Args, ValueEnum};
use mboxturbo::{
    CancelToken, Column, Compression, CsvExporter, Destination, EmlExporter, Export, ExportSummary,
    Exporter, FormulaEscaping, IndexOrigin, IndexPolicy, IpcExporter, JsonlExporter, Mailbox,
    MailboxBuilder, MboxExporter, MboxTurboError, Overwrite, ParquetExporter, Pipeline, Progress,
    Selection,
};

use crate::events::{self, Counts, File, Report, Start, Summary, Throttle};
use crate::exit::{self, Stage};
use crate::progress::{self, Bar, Feedback};
use crate::select::{self, SelectError};
use crate::signals::Interrupts;

/// Messages per batch: the unit the pipeline extracts and a sink writes at a time.
const BATCH_SIZE: usize = 4096;
/// The `--output` value that means standard output.
const STDOUT: &str = "-";

/// Why an export failed, and so which exit code it gets.
#[derive(Debug)]
pub(crate) enum Failure {
    /// The library failed at this stage.
    Core {
        /// The library error.
        error: Box<MboxTurboError>,
        /// Whether the mailbox was open when it failed.
        stage: Stage,
    },
    /// A termination signal stopped the export; the process exits with the signal's code.
    Interrupted {
        /// The library's cancellation error.
        error: Box<MboxTurboError>,
        /// The exit code of the signal that arrived.
        code: u8,
    },
    /// The command line was well formed but asks for something that cannot be done.
    Usage(String),
}

impl Failure {
    /// A library failure after the mailbox is open.
    const fn after_open(error: Box<MboxTurboError>) -> Self {
        Self::Core {
            error,
            stage: Stage::AfterOpen,
        }
    }

    /// The process exit code for this failure.
    pub(crate) fn code(&self) -> u8 {
        match self {
            Self::Core { error, stage } => exit::error_code(*stage, error),
            Self::Interrupted { code, .. } => *code,
            Self::Usage(_) => exit::USAGE,
        }
    }
}

impl fmt::Display for Failure {
    #[expect(
        clippy::renamed_function_params,
        reason = "the trait calls it `f`, a one-letter name the min_ident_chars lint bans"
    )]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core { error, .. } => write_chain(formatter, error),
            Self::Interrupted { error, .. } => {
                formatter.write_str("interrupted: ")?;
                write_chain(formatter, error)
            },
            Self::Usage(message) => formatter.write_str(message),
        }
    }
}

impl From<SelectError> for Failure {
    fn from(error: SelectError) -> Self {
        Self::Usage(error.to_string())
    }
}

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

    /// Whether this format can be written to standard output.
    const fn streams(self) -> bool {
        !matches!(self, Self::Eml | Self::Parquet)
    }
}

/// The messages an export writes and how many there are.
struct Selected {
    /// How many messages `selection` holds.
    count: usize,
    /// What the library is asked to write.
    selection: Selection,
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
/// anything is written; a [`Failure::Core`] for everything the library refuses, and for an event
/// that cannot be written to standard output.
pub(crate) fn run(args: &ExportArgs, report: Report, feedback: Feedback) -> Result<(), Failure> {
    refuse_events_on_stdout(args, report)?;
    let columns = columns(args.format, args.columns.as_deref())?;
    let destination = destination(args.format, &args.output)?;
    let ranges = select::parse_all(&args.select)?;
    let mailbox = open(&args.mailbox, args.index.as_deref())?;
    let selected = selection(args, ranges, &mailbox)?;
    let pipeline = Arc::new(Pipeline::new(columns, BATCH_SIZE));
    let exporter = args.format.exporter(mailbox.len());
    let origin = mailbox.index_origin();
    let export = Export::new(pipeline, Arc::new(mailbox), destination)
        .selection(selected.selection)
        .overwrite(args.overwrite_policy());
    let reported = Reported {
        args,
        count: selected.count,
        feedback,
        origin,
        report,
    };
    progress::note_origin(feedback, origin).map_err(stderr_failure)?;
    run_export(export, exporter, &reported)
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
    let cancel = CancelToken::new();
    let interrupts = Interrupts::watch(cancel.clone()).map_err(signal_failure)?;
    let mut observer = Observer::new(reported, Arc::clone(&failure), cancel.clone());
    let result = export
        .cancel_token(cancel)
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
    let summary = result.map_err(|error| core_failure(error, &interrupts))?;
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
        None => Failure::after_open(Box::new(error)),
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
    progress::print_summary(reported.feedback, summary, path).map_err(stderr_failure)
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
    })
}

/// Writes `error` and each of its causes, separated by `: `.
fn write_chain(formatter: &mut fmt::Formatter<'_>, error: &MboxTurboError) -> fmt::Result {
    write!(formatter, "{error}")?;
    let mut cause = error.source();
    while let Some(source) = cause {
        write!(formatter, ": {source}")?;
        cause = source.source();
    }
    Ok(())
}

/// An event that could not be written to standard output, as an I/O failure.
fn stdout_failure(source: io::Error) -> Failure {
    Failure::after_open(Box::new(MboxTurboError::Io {
        path: PathBuf::from("standard output"),
        source,
    }))
}

/// Signal handlers that could not be installed, as an I/O failure.
fn signal_failure(source: io::Error) -> Failure {
    Failure::after_open(Box::new(MboxTurboError::Io {
        path: PathBuf::from("signal handlers"),
        source,
    }))
}

/// A line that could not be written to standard error, as an I/O failure.
fn stderr_failure(source: io::Error) -> Failure {
    Failure::after_open(Box::new(MboxTurboError::Io {
        path: PathBuf::from("standard error"),
        source,
    }))
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
        Format::Mbox => Some(vec![Column::Raw]),
        Format::Arrow | Format::Csv | Format::Jsonl | Format::Parquet => None,
    };
    if let Some(fixed) = whole {
        if requested.is_some() {
            return Err(Failure::Usage(format!(
                "--columns cannot be used with {format:?}, which writes whole messages"
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
    if format.streams() {
        return Ok(Destination::Stream(Box::new(io::stdout())));
    }
    Err(Failure::Usage(format!(
        "{format:?} output cannot be written to standard output, so `-o -` is not allowed"
    )))
}

/// Opens the mailbox, with the index at `index` when one is named.
fn open(path: &Path, index: Option<&Path>) -> Result<Mailbox, Failure> {
    let policy = index.map_or(IndexPolicy::Sidecar, |index_path| {
        IndexPolicy::Path(index_path.to_path_buf())
    });
    MailboxBuilder::new()
        .index(policy)
        .open(path)
        .map_err(|error| {
            let stage = if is_missing(&error, path) {
                Stage::OpeningMailbox
            } else {
                Stage::AfterOpen
            };
            Failure::Core {
                error: Box::new(error),
                stage,
            }
        })
}

/// Whether `error` is the mailbox at `mailbox` not existing, as opposed to any other missing path
/// such as the index directory.
fn is_missing(error: &MboxTurboError, mailbox: &Path) -> bool {
    matches!(
        error,
        MboxTurboError::Io { path, source }
            if path == mailbox && source.kind() == io::ErrorKind::NotFound
    )
}

/// The messages to export: every message when no selection is given, otherwise the union of
/// `ranges` (from `--select`) and the `--select-file` lines.
fn selection(
    args: &ExportArgs,
    mut ranges: Vec<Range<usize>>,
    mailbox: &Mailbox,
) -> Result<Selected, Failure> {
    if args.select.is_empty() && args.select_file.is_none() {
        return Ok(Selected {
            count: mailbox.len(),
            selection: Selection::All,
        });
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
    let positions = select::positions(ranges, mailbox.len())?;
    Ok(Selected {
        count: positions.len(),
        selection: Selection::Positions(positions),
    })
}

/// The ranges named by the lines of the file at `path`; blank lines are ignored.
fn select_file(path: &Path) -> Result<Vec<Range<usize>>, Failure> {
    let text = fs::read_to_string(path).map_err(|source| {
        Failure::after_open(Box::new(MboxTurboError::Io {
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
