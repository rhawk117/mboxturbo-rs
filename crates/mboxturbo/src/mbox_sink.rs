//! The mbox sink of the export driver.

use arrow_array::RecordBatch;
use arrow_array::cast::AsArray as _;
use arrow_schema::{ArrowError, SchemaRef};

use crate::columns::Column;
use crate::error::MboxTurboError;
use crate::export::Exporter;
use crate::staging::{DestinationKind, Output, Staged};
use crate::width::widen;

/// The byte that ends a line.
const NEWLINE: u8 = b'\n';

/// Writes each selected message's stored bytes, `From ` separator line included, to a file or
/// stream, so the output is a mailbox holding the same messages in selection order.
///
/// The stored bytes are written unchanged, so `>From ` quoting already present in a message
/// stays as it is. A message whose stored bytes do not end in a newline gets exactly one
/// appended, so the next message's `From ` line starts a line. The export must extract
/// [`Column::Raw`]; [`Exporter::begin`] refuses a schema without it with an
/// [`MboxTurboError::Arrow`] schema error naming the column.
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
        raw_index(schema).map(drop)
    }

    fn finish(&mut self, _staged: &mut Staged) -> Result<u64, MboxTurboError> {
        Ok(0)
    }

    fn write(&mut self, batch: &RecordBatch, staged: &mut Staged) -> Result<u64, MboxTurboError> {
        let index = raw_index(&batch.schema())?;
        let mut encoded = Vec::new();
        for raw in batch.column(index).as_binary::<i64>().iter().flatten() {
            encoded.extend_from_slice(raw);
            if raw.last().is_some_and(|last| *last != NEWLINE) {
                encoded.push(NEWLINE);
            }
        }
        let Output::Writer(destination) = staged.output() else {
            // `accepts` refuses directory destinations
            return Err(staged.unsupported());
        };
        let written = destination.write_all(&encoded);
        written.map_err(|source| MboxTurboError::io(staged.target_label(), source))?;
        Ok(widen(encoded.len()))
    }
}

/// The position of the raw column in `schema`, or an Arrow schema error naming it.
fn raw_index(schema: &SchemaRef) -> Result<usize, MboxTurboError> {
    let name = Column::Raw.name();
    schema
        .index_of(&name)
        .map_err(|_missing| MboxTurboError::Arrow {
            positions: 0..0,
            source: ArrowError::SchemaError(format!("the `{name}` column was not extracted")),
        })
}
