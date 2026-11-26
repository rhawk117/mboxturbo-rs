/// The calls into the library that differ between the export driver and `write_parquet`.
mod api {
    #![expect(
        clippy::redundant_pub_crate,
        reason = "contradicts rustc's unreachable_pub, which is the lint this workspace keeps"
    )]

    use std::hint::black_box;
    use std::path::Path;
    use std::sync::Arc;

    use mboxturbo::{Compression, Mailbox, Pipeline};

    use super::Outcome;

    /// Passes every batch of the default columns through the reader and returns the rows seen.
    pub(crate) fn select_pass(pipeline: &Arc<Pipeline>, mailbox: &Arc<Mailbox>) -> Outcome<u64> {
        let mut rows = 0_usize;
        for batch in pipeline.reader(mailbox) {
            rows = rows.saturating_add(black_box(batch?).num_rows());
        }
        Ok(u64::try_from(rows)?)
    }

    /// A pipeline of the raw column alone, which `REF` may lack.
    pub(crate) fn raw_pipeline(_batch_size: usize) -> Option<Arc<Pipeline>> {
        None
    }

    /// Writes every message's columns of `pipeline` to a Parquet file at `path` compressed with
    /// `compression` and returns the rows written.
    pub(crate) fn parquet_pass(
        pipeline: &Arc<Pipeline>,
        mailbox: &Arc<Mailbox>,
        path: &Path,
        compression: Compression,
    ) -> Outcome<u64> {
        Ok(pipeline.write_parquet(mailbox, path, compression)?)
    }
}
