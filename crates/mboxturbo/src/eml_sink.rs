//! The EML directory sink of the export driver.

use std::borrow::Cow;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write as _};
use std::panic::resume_unwind;
use std::path::{Path, PathBuf};
use std::thread;

use arrow_array::cast::AsArray as _;
use arrow_array::types::{TimestampMicrosecondType, UInt64Type};
use arrow_array::{
    Array as _, LargeBinaryArray, RecordBatch, StringArray, TimestampMicrosecondArray, UInt64Array,
};
use arrow_schema::SchemaRef;
use mail_parser::DateTime;
use memchr::memmem;
use serde_json::{Value, json};

use crate::columns::Column;
use crate::encode::{column_index, null_error};
use crate::error::MboxTurboError;
use crate::export::Exporter;
use crate::staging::{DestinationKind, Output, Staged};
use crate::width::widen;

/// What error messages call this sink.
const SINK: &str = "EML";
/// The byte that ends a line.
const NEWLINE: u8 = b'\n';
/// The byte that quotes a `From ` line in mboxrd.
const QUOTE: u8 = b'>';
/// What a `From ` line starts with once its quoting is removed.
const FROM: &[u8] = b"From ";
/// What every `>+From ` line holds, so a body without it has no line to unquote.
const QUOTED_FROM: &[u8] = b">From ";
/// Microseconds in a second.
const MICROS_PER_SECOND: i64 = 1_000_000;
/// The manifest's file name.
const MANIFEST: &str = "manifest.jsonl";
/// The most threads that write files at once.
const MAX_WORKERS: usize = 8;
/// The fewest files a worker is given, so a small batch is not spread over threads.
const MIN_FILES_PER_WORKER: usize = 64;

/// Writes each selected message to its own `.eml` file in a directory, plus a `manifest.jsonl`.
///
/// A file is named by the message's position, zero-padded to the digit width of the mailbox's
/// message count, so no file name derives from message content. It holds the stored bytes
/// without the `From ` separator line, with one `>` removed from each line matching `>+From `
/// (mboxrd). The manifest has one JSON object per message in selection order, mapping
/// `position` to `file`, `message_id` and `date` (RFC 3339 UTC); the last two are `null` when
/// the message has none or the export did not extract them. The export must extract
/// [`Column::Raw`] and [`Column::Position`]; [`Exporter::begin`] refuses a schema without them
/// with an [`MboxTurboError::UnsupportedColumn`] naming the column and the sink. Only directory
/// destinations are accepted.
#[derive(Debug)]
pub struct EmlExporter {
    /// The manifest, open between `begin` and `finish`.
    manifest: Option<BufWriter<File>>,
    /// Digits in a file name's position.
    width: usize,
}

impl EmlExporter {
    /// The file name of the message at `position`.
    fn file_name(&self, position: u64) -> String {
        format!("{position:0width$}.eml", width = self.width)
    }

    /// A sink for a mailbox of `message_count` messages, which sets the zero-pad width of the
    /// file names.
    #[must_use]
    pub fn new(message_count: usize) -> Self {
        Self {
            manifest: None,
            width: message_count.to_string().len(),
        }
    }

    /// Appends one manifest line.
    fn write_entry(&mut self, entry: &Value, label: &Path) -> Result<(), MboxTurboError> {
        let Some(manifest) = self.manifest.as_mut() else {
            return Err(MboxTurboError::io(
                label,
                io::Error::other("the manifest is not open: `begin` was not called"),
            ));
        };
        serde_json::to_writer(&mut *manifest, entry)
            .map_err(|source| MboxTurboError::io(label, source.into()))?;
        manifest
            .write_all(&[NEWLINE])
            .map_err(|source| MboxTurboError::io(label, source))
    }
}

impl Exporter for EmlExporter {
    fn accepts(&self, kind: DestinationKind) -> bool {
        kind == DestinationKind::Directory
    }

    fn begin(&mut self, schema: &SchemaRef, staged: &mut Staged) -> Result<(), MboxTurboError> {
        column_index(schema, &Column::Raw, SINK).map(drop)?;
        column_index(schema, &Column::Position, SINK).map(drop)?;
        let Output::Directory(directory) = staged.output() else {
            // `accepts` refuses every other destination
            return Err(staged.unsupported());
        };
        let path = directory.join(MANIFEST);
        let file = File::create(&path).map_err(|source| MboxTurboError::io(&path, source))?;
        self.manifest = Some(BufWriter::new(file));
        Ok(())
    }

    fn finish(&mut self, staged: &mut Staged) -> Result<u64, MboxTurboError> {
        if let Some(mut manifest) = self.manifest.take() {
            let flushed = manifest.flush();
            flushed.map_err(|source| MboxTurboError::io(staged.target_label(), source))?;
        }
        Ok(0)
    }

    fn write(&mut self, batch: &RecordBatch, staged: &mut Staged) -> Result<u64, MboxTurboError> {
        let columns = Columns::new(batch)?;
        let label = staged.target_label().to_path_buf();
        let Output::Directory(directory) = staged.output() else {
            // `accepts` refuses every other destination
            return Err(staged.unsupported());
        };
        let mut files = Vec::with_capacity(batch.num_rows());
        for row in 0..batch.num_rows() {
            let (position, raw) = columns.message(row)?;
            let name = self.file_name(position);
            files.push(EmlFile {
                path: directory.join(&name),
                name,
                position,
                raw,
            });
        }
        let bytes = write_files(&files)?;
        for (row, file) in files.iter().enumerate() {
            self.write_entry(&columns.entry(row, file.position, &file.name), &label)?;
        }
        Ok(bytes)
    }
}

/// A message's position and its stored bytes, `From ` separator line and quoting included.
type Message<'batch> = (u64, &'batch [u8]);

/// One message's file, ready to write.
struct EmlFile<'batch> {
    /// The file name, as the manifest lists it.
    name: String,
    /// Where the file goes.
    path: PathBuf,
    /// The message's position.
    position: u64,
    /// The stored message bytes, `From ` separator line and quoting included.
    raw: &'batch [u8],
}

/// The columns of a batch that the sink reads.
struct Columns<'batch> {
    /// `date`, when extracted.
    dates: Option<&'batch TimestampMicrosecondArray>,
    /// `message_id`, when extracted.
    ids: Option<&'batch StringArray>,
    /// `position`.
    positions: &'batch UInt64Array,
    /// `raw`.
    raws: &'batch LargeBinaryArray,
}

impl<'batch> Columns<'batch> {
    /// The manifest object of the message at `row`.
    fn entry(&self, row: usize, position: u64, file: &str) -> Value {
        let message_id = self
            .ids
            .filter(|array| !array.is_null(row))
            .map(|array| array.value(row));
        let date = self
            .dates
            .filter(|array| !array.is_null(row))
            .map(|array| rfc3339(array.value(row)));
        json!({
            "position": position,
            "file": file,
            "message_id": message_id,
            "date": date,
        })
    }

    /// The position and the stored bytes of the message at `row`.
    fn message(&self, row: usize) -> Result<Message<'batch>, MboxTurboError> {
        if self.raws.is_null(row) || self.positions.is_null(row) {
            return Err(null_error(row));
        }
        Ok((self.positions.value(row), self.raws.value(row)))
    }

    /// The columns of `batch`, or an Arrow schema error naming a missing `raw` or `position`.
    fn new(batch: &'batch RecordBatch) -> Result<Self, MboxTurboError> {
        let schema = batch.schema();
        Ok(Self {
            dates: optional_index(&schema, &Column::Date).map(|index| {
                batch
                    .column(index)
                    .as_primitive::<TimestampMicrosecondType>()
            }),
            ids: optional_index(&schema, &Column::MessageId)
                .map(|index| batch.column(index).as_string::<i32>()),
            positions: batch
                .column(column_index(&schema, &Column::Position, SINK)?)
                .as_primitive::<UInt64Type>(),
            raws: batch
                .column(column_index(&schema, &Column::Raw, SINK)?)
                .as_binary::<i64>(),
        })
    }
}

/// The index of `column` in `schema`, or `None` when the export did not extract it.
fn optional_index(schema: &SchemaRef, column: &Column) -> Option<usize> {
    schema
        .column_with_name(&column.name())
        .map(|(index, _field)| index)
}

/// `micros` since the epoch as an RFC 3339 UTC string, to the second.
fn rfc3339(micros: i64) -> String {
    DateTime::from_timestamp(micros.div_euclid(MICROS_PER_SECOND)).to_rfc3339()
}

/// `raw` without its `From ` separator line, with one `>` removed from each `>+From ` line.
///
/// Borrows the body when no line is quoted, which is most messages, and copies it otherwise.
fn unquote(raw: &[u8]) -> Cow<'_, [u8]> {
    // A message with no newline, or whose first line ends the bytes, has no body, so empty is
    // the right body; `end` indexes a byte of `raw`, so `get` is never out of range.
    let body = memchr::memchr(NEWLINE, raw).map_or(&[][..], |end| {
        raw.get(end.saturating_add(1)..).unwrap_or(&[])
    });
    if memmem::find(body, QUOTED_FROM).is_none() {
        return Cow::Borrowed(body);
    }
    let mut out = Vec::with_capacity(body.len());
    for line in body.split_inclusive(|byte| *byte == NEWLINE) {
        out.extend_from_slice(if is_quoted_from(line) {
            line.get(1..).unwrap_or(line)
        } else {
            line
        });
    }
    Cow::Owned(out)
}

/// Whether `line` matches `>+From `.
fn is_quoted_from(line: &[u8]) -> bool {
    let quotes = line.iter().take_while(|byte| **byte == QUOTE).count();
    quotes > 0
        && line
            .get(quotes..)
            .is_some_and(|rest| rest.starts_with(FROM))
}

/// Writes the unquoted bytes of `file` to its path and returns how many there were.
fn write_file(file: &EmlFile<'_>) -> Result<u64, MboxTurboError> {
    let eml = unquote(file.raw);
    fs::write(&file.path, &eml).map_err(|source| MboxTurboError::io(&file.path, source))?;
    Ok(widen(eml.len()))
}

/// Writes each file of `files` from up to [`MAX_WORKERS`] scoped threads, each taking a
/// contiguous chunk, and returns the bytes written, or the first error by position order.
///
/// Every thread is joined before this returns, so no write is in flight afterwards; a chunk after
/// the failing one may still have written its files.
fn write_files(files: &[EmlFile<'_>]) -> Result<u64, MboxTurboError> {
    let available = thread::available_parallelism().map_or(1, usize::from);
    let workers = available
        .min(MAX_WORKERS)
        .min(files.len().div_ceil(MIN_FILES_PER_WORKER))
        .max(1);
    let write_chunk = |chunk: &[EmlFile<'_>]| {
        chunk.iter().try_fold(0_u64, |total, file| {
            write_file(file).map(|bytes| total.saturating_add(bytes))
        })
    };
    if workers == 1 {
        return write_chunk(files);
    }
    thread::scope(|scope| {
        let handles: Vec<_> = files
            .chunks(files.len().div_ceil(workers))
            .map(|chunk| scope.spawn(move || write_chunk(chunk)))
            .collect();
        let mut total = Ok(0_u64);
        for handle in handles {
            let result = handle.join().unwrap_or_else(|panic| resume_unwind(panic));
            total = total.and_then(|sum: u64| result.map(|bytes| sum.saturating_add(bytes)));
        }
        total
    })
}
