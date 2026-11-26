//! The Parquet sink of the export driver.

use std::io;
use std::path::Path;

use arrow_array::RecordBatch;
use arrow_schema::SchemaRef;
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression as ParquetCompression, ZstdLevel};
use parquet::errors::ParquetError;
use parquet::file::properties::{EnabledStatistics, WriterProperties};

use crate::error::MboxTurboError;
use crate::export::{DestinationKind, Exporter};
use crate::pipeline::Compression;
use crate::staging::Staged;

/// Rows per row group: 16 batches of the default 8192.
const ROW_GROUP_ROWS: usize = 0x0002_0000;

/// Where a Parquet failure is reported when the destination is a stream.
const STREAM: &str = "<stream>";

/// Writes the exported columns as one Parquet file.
///
/// Accepts a file or a stream destination and refuses a directory. The file holds one column
/// per selected [`Column`](crate::Column), in order, with the Arrow schema embedded, so it reads
/// back with the same types the pipeline produced. Dictionary encoding is off and statistics are
/// kept per column chunk.
///
/// The byte count the driver reports covers the row groups written so far; the footer written by
/// [`Exporter::finish`] is not counted, because only [`Exporter::write`] returns a count.
#[derive(Debug)]
pub struct ParquetExporter {
    /// Page compression.
    compression: Compression,
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
            writer: None,
        }
    }
}

impl Exporter for ParquetExporter {
    fn accepts(&self, kind: DestinationKind) -> bool {
        kind != DestinationKind::Directory
    }

    fn begin(&mut self, schema: &SchemaRef, staged: &mut Staged) -> Result<(), MboxTurboError> {
        let properties = WriterProperties::builder()
            .set_compression(parquet_compression(self.compression))
            .set_max_row_group_row_count(Some(ROW_GROUP_ROWS))
            .set_dictionary_enabled(false)
            .set_statistics_enabled(EnabledStatistics::Chunk)
            .build();
        let writer = ArrowWriter::try_new(Vec::new(), SchemaRef::clone(schema), Some(properties))
            .map_err(|source| parquet_failure(staged, source))?;
        self.writer = Some(writer);
        Ok(())
    }

    fn finish(&mut self, staged: &mut Staged) -> Result<(), MboxTurboError> {
        let writer = self.encoder(staged)?;
        let _metadata = writer
            .finish()
            .map_err(|source| parquet_failure(staged, source))?;
        drain(writer, staged).map(|_bytes| ())
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
    let bytes = count(pending.len());
    let target = staged.target().map(ToOwned::to_owned);
    let path = target.as_deref().unwrap_or_else(|| Path::new(STREAM));
    let Some(destination) = staged.writer() else {
        return Err(MboxTurboError::io(
            path,
            io::Error::other("a Parquet file needs a file or stream destination"),
        ));
    };
    destination
        .write_all(pending)
        .map_err(|source| MboxTurboError::io(path, source))?;
    pending.clear();
    Ok(bytes)
}

/// A byte count as `u64`, saturating on a platform where `usize` is wider.
#[expect(
    clippy::disallowed_methods,
    reason = "saturating is the right answer on a hypothetical wider usize"
)]
fn count(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
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

/// A Parquet failure on the destination `staged` writes to.
fn parquet_failure(staged: &Staged, source: ParquetError) -> MboxTurboError {
    MboxTurboError::Parquet {
        path: staged
            .target()
            .map_or_else(|| Path::new(STREAM).to_path_buf(), Path::to_path_buf),
        source,
    }
}
