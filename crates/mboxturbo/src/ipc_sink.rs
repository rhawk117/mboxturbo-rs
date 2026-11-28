//! The Arrow IPC stream sink of the export driver.

use std::fmt;

use arrow_array::RecordBatch;
use arrow_ipc::writer::StreamWriter;
use arrow_schema::{ArrowError, SchemaRef};

use crate::encode::{encode_failure, write_stream};
use crate::error::MboxTurboError;
use crate::export::Exporter;
use crate::staging::{DestinationKind, Staged};

/// What error messages call this sink.
const SINK: &str = "Arrow IPC";

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
    fn encoder(&mut self, staged: &Staged) -> Result<&mut StreamWriter<Vec<u8>>, MboxTurboError> {
        self.writer.as_mut().ok_or_else(|| {
            encode_failure(
                SINK,
                staged,
                ArrowError::InvalidArgumentError("the sink was written to before it began".into()),
            )
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

    fn begin(&mut self, schema: &SchemaRef, staged: &mut Staged) -> Result<(), MboxTurboError> {
        // the schema message stays pending and is counted with the first batch
        let writer = StreamWriter::try_new(Vec::new(), schema)
            .map_err(|source| encode_failure(SINK, staged, source))?;
        self.writer = Some(writer);
        Ok(())
    }

    fn finish(&mut self, staged: &mut Staged) -> Result<u64, MboxTurboError> {
        let writer = self.encoder(staged)?;
        writer
            .finish()
            .map_err(|source| encode_failure(SINK, staged, source))?;
        drain(writer, staged)
    }

    fn write(&mut self, batch: &RecordBatch, staged: &mut Staged) -> Result<u64, MboxTurboError> {
        let writer = self.encoder(staged)?;
        writer
            .write(batch)
            .map_err(|source| encode_failure(SINK, staged, source))?;
        drain(writer, staged)
    }
}

/// Moves the bytes the encoder has produced into the staged destination and returns how many.
fn drain(writer: &mut StreamWriter<Vec<u8>>, staged: &mut Staged) -> Result<u64, MboxTurboError> {
    let pending = writer.get_mut();
    let bytes = write_stream(staged, pending)?;
    pending.clear();
    Ok(bytes)
}
