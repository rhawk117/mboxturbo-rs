//! The mbox sink of the export driver.

use arrow_array::cast::AsArray as _;
use arrow_array::{Array as _, RecordBatch};
use arrow_schema::SchemaRef;

use crate::columns::Column;
use crate::encode::{column_index, null_error, write_stream};
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
/// fails the write as in the EML sink.
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
                return Err(null_error(row));
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

    #[test]
    fn a_null_raw_value_fails_the_write_as_the_eml_sink_does() {
        let directory = tempfile::tempdir().expect("the directory is created");
        let target = directory.path().join("out.mbox");
        let mut staged = Destination::File(target)
            .stage(Overwrite::Refuse)
            .expect("the destination stages");
        let schema = Arc::new(Schema::new(vec![Field::new(
            "raw",
            DataType::LargeBinary,
            true,
        )]));
        let raws: ArrayRef = Arc::new(LargeBinaryArray::from(vec![
            Some(&b"From a\n\nbody\n"[..]),
            None,
        ]));
        let batch =
            RecordBatch::try_new(Arc::clone(&schema), vec![raws]).expect("the batch is valid");
        let mut exporter = MboxExporter::new();
        exporter
            .begin(&schema, &mut staged)
            .expect("the schema holds raw");
        let error = exporter
            .write(&batch, &mut staged)
            .expect_err("a null raw value cannot be written");
        assert!(
            matches!(&error, MboxTurboError::Arrow { positions, .. } if *positions == (1..2)),
            "the null row is named: {error:?}"
        );
    }
}
