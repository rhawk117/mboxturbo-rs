//! The Parquet sink of the export driver.

use std::io;

use arrow_array::RecordBatch;
use arrow_schema::SchemaRef;
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression as ParquetCompression, ZstdLevel};
use parquet::errors::ParquetError;
use parquet::file::properties::{EnabledStatistics, WriterProperties};

use crate::encode::write_stream;
use crate::error::MboxTurboError;
use crate::export::Exporter;
use crate::pipeline::Compression;
use crate::staging::{DestinationKind, Staged};

/// Rows per row group: 16 batches of the default 8192.
const ROW_GROUP_ROWS: usize = 0x0002_0000;
/// Batches per row group when the row group is sized from the batch size.
const ROW_GROUP_BATCHES: usize = 16;

/// Writes the exported columns as one Parquet file.
///
/// Accepts a file or a stream destination and refuses a directory. The file holds one column
/// per selected [`Column`](crate::Column), in order, with the Arrow schema embedded, so it reads
/// back with the same types the pipeline produced. Dictionary encoding is off and statistics are
/// kept per column chunk.
///
/// The byte count the driver reports covers every byte written, the footer included, because
/// [`Exporter::finish`] returns the footer's size.
#[derive(Debug)]
pub struct ParquetExporter {
    /// Page compression.
    compression: Compression,
    /// The most rows in one row group.
    row_group_rows: usize,
    /// The encoder, created by `begin` and holding at most the unwritten tail of the file.
    writer: Option<ArrowWriter<Vec<u8>>>,
}

impl ParquetExporter {
    /// The encoder, or a failure when the driver skipped `begin`.
    fn encoder(&mut self, staged: &Staged) -> Result<&mut ArrowWriter<Vec<u8>>, MboxTurboError> {
        self.writer.as_mut().ok_or_else(|| {
            parquet_failure(
                staged,
                ParquetError::General("the sink was written to before it began".into()),
            )
        })
    }

    /// A sink that compresses pages with `compression`.
    #[must_use]
    pub const fn new(compression: Compression) -> Self {
        Self {
            compression,
            row_group_rows: ROW_GROUP_ROWS,
            writer: None,
        }
    }

    /// The same sink with row groups of 16 batches of `batch_size` rows each, so a row group
    /// closes on a batch boundary.
    #[must_use]
    pub fn with_row_group_batches(self, batch_size: usize) -> Self {
        self.with_row_group_rows(batch_size.saturating_mul(ROW_GROUP_BATCHES))
    }

    /// The same sink with row groups of at most `rows` rows (at least one); the default is
    /// 131072.
    #[must_use]
    pub fn with_row_group_rows(mut self, rows: usize) -> Self {
        self.row_group_rows = rows.max(1);
        self
    }
}

impl Exporter for ParquetExporter {
    fn accepts(&self, kind: DestinationKind) -> bool {
        kind != DestinationKind::Directory
    }

    fn begin(&mut self, schema: &SchemaRef, staged: &mut Staged) -> Result<(), MboxTurboError> {
        let properties = WriterProperties::builder()
            .set_compression(parquet_compression(self.compression))
            .set_max_row_group_row_count(Some(self.row_group_rows))
            .set_dictionary_enabled(false)
            .set_statistics_enabled(EnabledStatistics::Chunk)
            .build();
        let writer = ArrowWriter::try_new(Vec::new(), SchemaRef::clone(schema), Some(properties))
            .map_err(|source| parquet_failure(staged, source))?;
        self.writer = Some(writer);
        Ok(())
    }

    fn finish(&mut self, staged: &mut Staged) -> Result<u64, MboxTurboError> {
        let writer = self.encoder(staged)?;
        let _metadata = writer
            .finish()
            .map_err(|source| parquet_failure(staged, source))?;
        drain(writer, staged)
    }

    fn write(&mut self, batch: &RecordBatch, staged: &mut Staged) -> Result<u64, MboxTurboError> {
        let writer = self.encoder(staged)?;
        writer
            .write(batch)
            .map_err(|source| parquet_failure(staged, source))?;
        drain(writer, staged)
    }
}

/// Moves the bytes the encoder has finished into the staged destination and returns how many.
fn drain(writer: &mut ArrowWriter<Vec<u8>>, staged: &mut Staged) -> Result<u64, MboxTurboError> {
    let pending = writer.inner_mut();
    let bytes = write_stream(staged, pending)?;
    pending.clear();
    Ok(bytes)
}

/// Maps the public [`Compression`] choice to the Parquet writer's codec (Zstd at its default
/// level).
fn parquet_compression(compression: Compression) -> ParquetCompression {
    match compression {
        Compression::Zstd => ParquetCompression::ZSTD(ZstdLevel::default()),
        Compression::Snappy => ParquetCompression::SNAPPY,
        Compression::Uncompressed => ParquetCompression::UNCOMPRESSED,
    }
}

/// A Parquet failure on the destination `staged` writes to: [`MboxTurboError::Parquet`] naming
/// the file, or [`MboxTurboError::Stream`] for a stream, which has no path to name.
fn parquet_failure(staged: &Staged, source: ParquetError) -> MboxTurboError {
    match staged.target() {
        Some(path) => MboxTurboError::Parquet {
            path: path.to_path_buf(),
            source,
        },
        None => MboxTurboError::Stream {
            source: io::Error::other(source),
        },
    }
}
