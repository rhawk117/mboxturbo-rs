//! The EML directory sink of the export driver.

use std::fs::{self, File};
use std::io::{self, BufWriter, Write as _};
use std::path::Path;

use arrow_array::cast::AsArray as _;
use arrow_array::types::{TimestampMicrosecondType, UInt64Type};
use arrow_array::{
    Array as _, LargeBinaryArray, RecordBatch, StringArray, TimestampMicrosecondArray, UInt64Array,
};
use arrow_schema::{ArrowError, SchemaRef};
use mail_parser::DateTime;
use serde_json::{Value, json};

use crate::columns::Column;
use crate::error::MboxTurboError;
use crate::export::Exporter;
use crate::staging::{DestinationKind, Output, Staged};
use crate::width::widen;

/// The byte that ends a line.
const NEWLINE: u8 = b'\n';
/// The byte that quotes a `From ` line in mboxrd.
const QUOTE: u8 = b'>';
/// What a `From ` line starts with once its quoting is removed.
const FROM: &[u8] = b"From ";
/// Microseconds in a second.
const MICROS_PER_SECOND: i64 = 1_000_000;
/// The manifest's file name.
const MANIFEST: &str = "manifest.jsonl";

/// Writes each selected message to its own `.eml` file in a directory, plus a `manifest.jsonl`.
///
/// A file is named by the message's position, zero-padded to the digit width of the mailbox's
/// message count, so no file name derives from message content. It holds the stored bytes
/// without the `From ` separator line, with one `>` removed from each line matching `>+From `
/// (mboxrd). The manifest has one JSON object per message in selection order, mapping
/// `position` to `file`, `message_id` and `date` (RFC 3339 UTC); the last two are `null` when
/// the message has none or the export did not extract them. The export must extract
/// [`Column::Raw`] and [`Column::Position`]; [`Exporter::begin`] refuses a schema without them
/// with an [`MboxTurboError::Arrow`] schema error naming the column. Only directory
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
        column_index(schema, &Column::Raw).map(drop)?;
        column_index(schema, &Column::Position).map(drop)?;
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
        let mut bytes = 0_u64;
        for row in 0..batch.num_rows() {
            let (position, eml) = columns.message(row)?;
            let name = self.file_name(position);
            let path = directory.join(&name);
            fs::write(&path, &eml).map_err(|source| MboxTurboError::io(&path, source))?;
            bytes = bytes.saturating_add(widen(eml.len()));
            self.write_entry(&columns.entry(row, position, &name), &label)?;
        }
        Ok(bytes)
    }
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

    /// The position and the EML bytes of the message at `row`.
    fn message(&self, row: usize) -> Result<(u64, Vec<u8>), MboxTurboError> {
        if self.raws.is_null(row) || self.positions.is_null(row) {
            return Err(null_error(row));
        }
        Ok((self.positions.value(row), unquote(self.raws.value(row))))
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
                .column(column_index(&schema, &Column::Position)?)
                .as_primitive::<UInt64Type>(),
            raws: batch
                .column(column_index(&schema, &Column::Raw)?)
                .as_binary::<i64>(),
        })
    }
}

/// The index of `column` in `schema`, or an Arrow schema error naming it.
fn column_index(schema: &SchemaRef, column: &Column) -> Result<usize, MboxTurboError> {
    let name = column.name();
    schema
        .index_of(&name)
        .map_err(|_missing| MboxTurboError::Arrow {
            positions: 0..0,
            source: ArrowError::SchemaError(format!("the `{name}` column was not extracted")),
        })
}

/// The index of `column` in `schema`, or `None` when the export did not extract it.
fn optional_index(schema: &SchemaRef, column: &Column) -> Option<usize> {
    schema
        .column_with_name(&column.name())
        .map(|(index, _field)| index)
}

/// The error for a null `raw` or `position` value at `row` of a batch.
fn null_error(row: usize) -> MboxTurboError {
    MboxTurboError::Arrow {
        positions: row..row.saturating_add(1),
        source: ArrowError::SchemaError("the `raw` and `position` columns must not be null".into()),
    }
}

/// `micros` since the epoch as an RFC 3339 UTC string, to the second.
fn rfc3339(micros: i64) -> String {
    DateTime::from_timestamp(micros.div_euclid(MICROS_PER_SECOND)).to_rfc3339()
}

/// `raw` without its `From ` separator line, with one `>` removed from each `>+From ` line.
fn unquote(raw: &[u8]) -> Vec<u8> {
    let body = raw
        .iter()
        .position(|byte| *byte == NEWLINE)
        .map_or(&[][..], |end| {
            raw.get(end.saturating_add(1)..).unwrap_or(&[])
        });
    let mut out = Vec::with_capacity(body.len());
    for line in body.split_inclusive(|byte| *byte == NEWLINE) {
        out.extend_from_slice(if is_quoted_from(line) {
            line.get(1..).unwrap_or(line)
        } else {
            line
        });
    }
    out
}

/// Whether `line` matches `>+From `.
fn is_quoted_from(line: &[u8]) -> bool {
    let quotes = line.iter().take_while(|byte| **byte == QUOTE).count();
    quotes > 0
        && line
            .get(quotes..)
            .is_some_and(|rest| rest.starts_with(FROM))
}
