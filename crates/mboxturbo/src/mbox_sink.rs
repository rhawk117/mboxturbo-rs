//! The mbox sink of the export driver.

use arrow_array::cast::AsArray as _;
use arrow_array::{Array as _, RecordBatch};
use arrow_schema::{ArrowError, SchemaRef};

use crate::columns::Column;
use crate::encode::{column_index, encode_failure, write_stream};
use crate::error::MboxTurboError;
use crate::export::Exporter;
use crate::staging::{DestinationKind, Staged};

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
/// [`MboxTurboError::UnsupportedColumn`] naming the column and the sink, and a null raw value
/// fails the write with an [`MboxTurboError::Encode`] naming the batch row.
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
        let mut encoded = Vec::new();
        for row in 0..raws.len() {
            if raws.is_null(row) {
                return Err(encode_failure(
                    SINK,
                    staged,
                    ArrowError::SchemaError(format!("row {row} of a batch has no raw value")),
                ));
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

    use arrow_array::{ArrayRef, LargeBinaryArray, RecordBatch};
    use arrow_schema::{DataType, Field, Schema};

    use super::MboxExporter;
    use crate::error::MboxTurboError;
    use crate::export::Exporter as _;
    use crate::staging::{Destination, Overwrite};

    /// A batch of two messages, the second with no raw value.
    fn batch_with_a_null() -> RecordBatch {
        let raws: ArrayRef = Arc::new(LargeBinaryArray::from(vec![
            Some(&b"From a\n\nbody\n"[..]),
            None,
        ]));
        let field = Field::new("raw", DataType::LargeBinary, true);
        RecordBatch::try_new(Arc::new(Schema::new(vec![field])), vec![raws])
            .expect("the batch is valid")
    }

    #[test]
    fn a_null_raw_value_fails_the_write_naming_the_batch_row() {
        let directory = tempfile::tempdir().expect("the directory is created");
        let mut staged = Destination::File(directory.path().join("out.mbox"))
            .stage(Overwrite::Refuse)
            .expect("the destination stages");
        let error = MboxExporter::new()
            .write(&batch_with_a_null(), &mut staged)
            .expect_err("a null raw value cannot be written");
        let MboxTurboError::Encode { sink, source, .. } = error else {
            panic!("a null raw value is an encoder failure");
        };
        assert_eq!(sink, "mbox", "the sink is named");
        assert!(
            source
                .to_string()
                .contains("row 1 of a batch has no raw value"),
            "the batch row is named: {source}"
        );
    }
}
