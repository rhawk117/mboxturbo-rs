//! The Arrow IPC stream sink of the export driver.

use std::fmt;

use arrow_array::RecordBatch;
use arrow_ipc::writer::StreamWriter;
use arrow_schema::{ArrowError, SchemaRef};

use crate::error::MboxTurboError;
use crate::export::Exporter;
use crate::staging::{DestinationKind, Output, Staged};
use crate::width::widen;

/// Writes the exported columns as an Arrow IPC stream.
///
/// Accepts a file or a stream destination and refuses a directory. The output is the streaming
/// format, not the file format: a schema message, one record batch message per exported batch,
/// and an end-of-stream marker, so it reads back with the same types the pipeline produced and
/// can be piped.
#[derive(Default)]
pub struct IpcExporter {
    /// The encoder, created by `begin` and holding at most the unwritten tail of the stream.
    writer: Option<StreamWriter<Vec<u8>>>,
}

impl IpcExporter {
    /// The encoder, or a failure when the driver skipped `begin`.
    fn encoder(&mut self) -> Result<&mut StreamWriter<Vec<u8>>, MboxTurboError> {
        self.writer.as_mut().ok_or_else(|| {
            arrow_failure(ArrowError::InvalidArgumentError(
                "the sink was written to before it began".into(),
            ))
        })
    }

    /// A sink that writes an Arrow IPC stream.
    #[must_use]
    pub const fn new() -> Self {
        Self { writer: None }
    }
}

impl fmt::Debug for IpcExporter {
    #[expect(
        clippy::renamed_function_params,
        reason = "the trait calls it `f`, a one-letter name the min_ident_chars lint bans"
    )]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IpcExporter")
            .field("begun", &self.writer.is_some())
            .finish()
    }
}

impl Exporter for IpcExporter {
    fn accepts(&self, kind: DestinationKind) -> bool {
        kind != DestinationKind::Directory
    }

    fn begin(&mut self, schema: &SchemaRef, _staged: &mut Staged) -> Result<(), MboxTurboError> {
        // the schema message stays pending and is counted with the first batch
        let writer = StreamWriter::try_new(Vec::new(), schema).map_err(arrow_failure)?;
        self.writer = Some(writer);
        Ok(())
    }

    fn finish(&mut self, staged: &mut Staged) -> Result<u64, MboxTurboError> {
        let writer = self.encoder()?;
        writer.finish().map_err(arrow_failure)?;
        drain(writer, staged)
    }

    fn write(&mut self, batch: &RecordBatch, staged: &mut Staged) -> Result<u64, MboxTurboError> {
        let writer = self.encoder()?;
        writer.write(batch).map_err(arrow_failure)?;
        drain(writer, staged)
    }
}

/// An Arrow failure not tied to a range of messages.
const fn arrow_failure(source: ArrowError) -> MboxTurboError {
    MboxTurboError::Arrow {
        positions: 0..0,
        source,
    }
}

/// Moves the bytes the encoder has produced into the staged destination and returns how many.
fn drain(writer: &mut StreamWriter<Vec<u8>>, staged: &mut Staged) -> Result<u64, MboxTurboError> {
    let pending = writer.get_mut();
    let bytes = widen(pending.len());
    let Output::Writer(destination) = staged.output() else {
        // `accepts` refuses directory destinations, so the driver never stages one for this sink
        return Err(staged.unsupported());
    };
    let written = destination.write_all(pending);
    written.map_err(|source| MboxTurboError::io(staged.target_label(), source))?;
    pending.clear();
    Ok(bytes)
}
