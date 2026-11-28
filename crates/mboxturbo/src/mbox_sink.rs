//! The mbox sink of the export driver.

use arrow_array::cast::AsArray as _;
use arrow_array::types::UInt64Type;
use arrow_array::{Array as _, RecordBatch};
use arrow_schema::{ArrowError, SchemaRef};

use crate::columns::Column;
use crate::encode::{column_index, optional_index, write_stream};
use crate::error::MboxTurboError;
use crate::export::Exporter;
use crate::staging::{DestinationKind, Staged};
use crate::width::narrow;

/// What error messages call this sink.
const SINK: &str = "mbox";

/// The byte that ends a line.
const NEWLINE: u8 = b'\n';

/// Writes each selected message's stored bytes, `From ` separator line included, to a file or
/// stream, so the output is a mailbox holding the same messages in selection order.
///
/// The stored bytes are written unchanged, so `>From ` quoting already present in a message
/// stays as it is. A message whose stored bytes do not end in a newline gets exactly one
/// appended, so the next message's `From ` line starts a line. The export must extract
/// [`Column::Raw`]; [`Exporter::begin`] refuses a schema without it with an
/// [`MboxTurboError::UnsupportedColumn`] naming the column and the sink. A batch that also
/// carries [`Column::Position`] lets a null raw value fail the write with an
/// [`MboxTurboError::Arrow`] naming that message's mailbox position; without it, or when the
/// position is null, the error names the batch row.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct MboxExporter;

impl MboxExporter {
    /// A sink that writes the raw column of each batch as an mbox.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Exporter for MboxExporter {
    fn accepts(&self, kind: DestinationKind) -> bool {
        kind != DestinationKind::Directory
    }

    fn begin(&mut self, schema: &SchemaRef, _staged: &mut Staged) -> Result<(), MboxTurboError> {
        column_index(schema, &Column::Raw, SINK).map(drop)
    }

    fn finish(&mut self, _staged: &mut Staged) -> Result<u64, MboxTurboError> {
        Ok(0)
    }

    fn write(&mut self, batch: &RecordBatch, staged: &mut Staged) -> Result<u64, MboxTurboError> {
        let index = column_index(&batch.schema(), &Column::Raw, SINK)?;
        let raws = batch.column(index).as_binary::<i64>();
        let positions = optional_index(&batch.schema(), &Column::Position)
            .map(|position| batch.column(position).as_primitive::<UInt64Type>());
        let mut encoded = Vec::new();
        for row in 0..raws.len() {
            if raws.is_null(row) {
                let start = positions
                    .filter(|column| !column.is_null(row))
                    .and_then(|column| narrow(column.value(row)))
                    .unwrap_or(row);
                return Err(MboxTurboError::Arrow {
                    positions: start..start.saturating_add(1),
                    source: ArrowError::SchemaError(
                        "the `raw` value of a message must not be null".into(),
                    ),
                });
            }
            let raw = raws.value(row);
            encoded.extend_from_slice(raw);
            if raw.last().is_some_and(|last| *last != NEWLINE) {
                encoded.push(NEWLINE);
            }
        }
        write_stream(staged, &encoded)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arrow_array::{ArrayRef, LargeBinaryArray, RecordBatch, UInt64Array};
    use arrow_schema::{DataType, Field, Schema};

    use super::MboxExporter;
    use crate::error::MboxTurboError;
    use crate::export::Exporter as _;
    use crate::staging::{Destination, Overwrite};

    /// A batch of two messages at mailbox positions 40 and 41, the second with no raw value.
    fn batch_with_a_null() -> RecordBatch {
        let raws: ArrayRef = Arc::new(LargeBinaryArray::from(vec![
            Some(&b"From a\n\nbody\n"[..]),
            None,
        ]));
        let positions: ArrayRef = Arc::new(UInt64Array::from(vec![40, 41]));
        let schema = Schema::new(vec![
            Field::new("raw", DataType::LargeBinary, true),
            Field::new("position", DataType::UInt64, false),
        ]);
        RecordBatch::try_new(Arc::new(schema), vec![raws, positions]).expect("the batch is valid")
    }

    #[test]
    fn a_null_raw_value_fails_the_write_naming_the_mailbox_position() {
        let directory = tempfile::tempdir().expect("the directory is created");
        let mut staged = Destination::File(directory.path().join("out.mbox"))
            .stage(Overwrite::Refuse)
            .expect("the destination stages");
        let error = MboxExporter::new()
            .write(&batch_with_a_null(), &mut staged)
            .expect_err("a null raw value cannot be written");
        let MboxTurboError::Arrow { positions, .. } = error else {
            panic!("a null raw value is an Arrow schema failure, got {error:?}");
        };
        assert_eq!(positions, 41..42, "the mailbox position is named");
    }
}
