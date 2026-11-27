//! The `export` subcommand: opens a mailbox and writes the selected messages in one format.

use std::error::Error as _;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{fmt, fs, io};

use clap::{Args, ValueEnum};
use mboxturbo::{
    Column, Compression, CsvExporter, Destination, EmlExporter, Export, Exporter, FormulaEscaping,
    IndexPolicy, IpcExporter, JsonlExporter, Mailbox, MailboxBuilder, MboxExporter, MboxTurboError,
    Overwrite, ParquetExporter, Pipeline, Selection,
};

use crate::exit::{self, Stage};
use crate::select::{self, SelectError};

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
            Self::Core { error, .. } => {
                write!(formatter, "{error}")?;
                let mut cause = error.source();
                while let Some(source) = cause {
                    write!(formatter, ": {source}")?;
                    cause = source.source();
                }
                Ok(())
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

    /// Whether this format can be written to standard output.
    const fn streams(self) -> bool {
        !matches!(self, Self::Eml | Self::Parquet)
    }
}

/// Runs the `export` subcommand.
///
/// # Errors
///
/// A [`Failure::Usage`] for an unknown column, a malformed or out-of-range selection, or
/// standard output with a format that cannot stream, all found before anything is written; a
/// [`Failure::Core`] for everything the library refuses.
pub(crate) fn run(args: &ExportArgs) -> Result<(), Failure> {
    let columns = columns(args.format, args.columns.as_deref())?;
    let destination = destination(args.format, &args.output)?;
    let ranges = select::parse_all(&args.select)?;
    let mailbox = open(&args.mailbox, args.index.as_deref())?;
    let selection = selection(args, ranges, &mailbox)?;
    let pipeline = Arc::new(Pipeline::new(columns, BATCH_SIZE));
    let exporter = args.format.exporter(mailbox.len());
    Export::new(pipeline, Arc::new(mailbox), destination)
        .selection(selection)
        .overwrite(args.overwrite_policy())
        .run(exporter)
        .map(|_summary| ())
        .map_err(|error| Failure::after_open(Box::new(error)))
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
) -> Result<Selection, Failure> {
    if args.select.is_empty() && args.select_file.is_none() {
        return Ok(Selection::All);
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
    Ok(Selection::Positions(select::positions(
        ranges,
        mailbox.len(),
    )?))
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
