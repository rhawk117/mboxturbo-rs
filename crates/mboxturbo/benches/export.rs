//! Harness-free timings of the default column select, of the Parquet export, of raw-only Parquet
//! exports, of a plain copy of the mailbox and of the mbox, EML, JSONL, CSV and IPC exports, over
//! the synthetic fixture the index bench uses. The rows, in print order, are `select`, `parquet`,
//! `raw-parquet`, `raw-parquet-uncompressed`, `copy`, `mbox`, `eml`, `eml-floor`, `jsonl`, `csv`
//! and `ipc`. `eml-floor` writes the files the `eml` row wrote, with the same worker count and
//! chunking but no manifest and no selection, so it is the least the `eml` row can take.
//! The raw-only export with compression off (`raw-parquet-uncompressed`) is the row held to three
//! times the copy; the zstd `raw-parquet` row is reported only, because compressing the raw bytes
//! is work a copy does not do.
//!
//! The fixture is the index bench's: `MBOXTURBO_BENCH_DIR` moves it, and
//! `MBOXTURBO_BENCH_MESSAGES` and `MBOXTURBO_BENCH_SEED` override its defaults of one million
//! messages and seed 1. Each row is the median of `RUNS` passes, in milliseconds per pass.

mod common;

// ab:api begin (scripts/bench-ab.sh swaps this block for scripts/ab/export_main.rs)
/// The calls into the library that differ between the export driver and `write_parquet`.
mod api {
    #![expect(
        clippy::redundant_pub_crate,
        reason = "contradicts rustc's unreachable_pub, which is the lint this workspace keeps"
    )]

    use std::hint::black_box;
    use std::path::Path;
    use std::sync::Arc;

    use mboxturbo::{
        Column, Compression, Destination, Export, Mailbox, Overwrite, ParquetExporter, Pipeline,
    };

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
    #[expect(
        clippy::unnecessary_wraps,
        reason = "the `REF` variant of this function has no raw column and returns `None`"
    )]
    pub(crate) fn raw_pipeline(batch_size: usize) -> Option<Arc<Pipeline>> {
        Some(Arc::new(Pipeline::new(vec![Column::Raw], batch_size)))
    }

    /// Writes every message's columns of `pipeline` to a Parquet file at `path` compressed with
    /// `compression` and returns the rows written.
    pub(crate) fn parquet_pass(
        pipeline: &Arc<Pipeline>,
        mailbox: &Arc<Mailbox>,
        path: &Path,
        compression: Compression,
    ) -> Outcome<u64> {
        let destination = Destination::File(path.to_path_buf());
        let summary = Export::new(Arc::clone(pipeline), Arc::clone(mailbox), destination)
            .overwrite(Overwrite::Replace)
            .run(Box::new(ParquetExporter::new(compression)))?;
        Ok(summary.messages)
    }
}
// ab:api end

use std::hint::black_box;
use std::io::{self, Write as _};
use std::panic::resume_unwind;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{fs, thread};

use common::Outcome;
use mboxturbo::{Column, Compression, Mailbox, Pipeline};

/// Messages in the fixture when `MBOXTURBO_BENCH_MESSAGES` is unset.
const DEFAULT_MESSAGES: u64 = 1_000_000;
/// Seed of the fixture when `MBOXTURBO_BENCH_SEED` is unset.
const DEFAULT_SEED: u64 = 1;
/// Rows per batch.
const BATCH_SIZE: usize = 8192;
/// Position of the median in the sorted timings.
const MEDIAN_RUN: usize = 2;
/// Passes timed per row.
const RUNS: usize = 5;

/// Times `RUNS` calls of `pass` and returns the median.
///
/// # Errors
///
/// Fails when a pass fails or reports a row count other than `expected`, so a pass that drops
/// batches cannot time faster unnoticed.
fn median(name: &str, expected: u64, pass: impl FnMut() -> Outcome<u64>) -> Outcome<Duration> {
    median_prepared(name, expected, || Ok(()), pass)
}

/// Like [`median`], but calls `prepare` before each pass, outside its timing.
fn median_prepared(
    name: &str,
    expected: u64,
    mut prepare: impl FnMut() -> Outcome<()>,
    mut pass: impl FnMut() -> Outcome<u64>,
) -> Outcome<Duration> {
    let mut runs = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        prepare()?;
        let start = Instant::now();
        let rows = black_box(pass()?);
        runs.push(start.elapsed());
        if rows != expected {
            return Err(format!("{name}: expected {expected} rows, got {rows}").into());
        }
    }
    runs.sort_unstable();
    Ok(runs.get(MEDIAN_RUN).copied().unwrap_or(Duration::ZERO))
}

/// Prints one row: the median pass in milliseconds, to 0.01 ms.
fn row(name: &str, elapsed: Duration) -> Outcome<()> {
    let micros = elapsed.as_micros();
    let text = format!(
        "{}.{:02}",
        micros.div_euclid(1000),
        micros.rem_euclid(1000).div_euclid(10)
    );
    writeln!(io::stdout().lock(), "{name:<26} {text:>12} ms")?;
    Ok(())
}

/// Times `pass` as `name` and prints its row.
fn report(name: &str, expected: u64, pass: impl FnMut() -> Outcome<u64>) -> Outcome<()> {
    row(name, median(name, expected, pass)?)
}

/// Times the mbox, EML, EML floor, JSONL, CSV and IPC exports into `scratch` and prints their
/// rows; the body is the block `REF` lacks the sinks for, so `REF` times nothing here.
#[expect(
    clippy::too_many_lines,
    reason = "the passes share one scratch directory and two selections"
)]
fn sink_rows(mailbox: &Arc<Mailbox>, scratch: &Path, expected: u64) -> Outcome<()> {
    // ab:new begin (scripts/bench-ab.sh drops this block from REF, which lacks these sinks)
    use mboxturbo::{
        CsvExporter, Destination, EmlExporter, Export, Exporter, FormulaEscaping, IpcExporter,
        JsonlExporter, MboxExporter, Overwrite,
    };

    fn export_pass(
        pipeline: &Arc<Pipeline>,
        mailbox: &Arc<Mailbox>,
        destination: Destination,
        exporter: Box<dyn Exporter>,
    ) -> Outcome<u64> {
        let summary = Export::new(Arc::clone(pipeline), Arc::clone(mailbox), destination)
            .overwrite(Overwrite::Replace)
            .run(exporter)?;
        Ok(summary.messages)
    }

    /// A file's name and bytes.
    type Named = (String, Vec<u8>);

    /// The files of the EML directory `directory` but its manifest, sorted by name.
    fn read_eml_files(directory: &Path) -> Outcome<Vec<Named>> {
        let mut files = Vec::new();
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            let name = path
                .file_name()
                .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
            if name != "manifest.jsonl" {
                files.push((name, fs::read(&path)?));
            }
        }
        files.sort_unstable();
        Ok(files)
    }

    /// Writes `files` into `directory` from the worker count and contiguous chunks that
    /// `EmlExporter` uses for one batch, and returns the first error by chunk order.
    fn write_batch(directory: &Path, files: &[Named]) -> io::Result<()> {
        const MAX_WORKERS: usize = 8;
        const MIN_FILES_PER_WORKER: usize = 64;
        let workers = thread::available_parallelism()
            .map_or(1, usize::from)
            .min(MAX_WORKERS)
            .min(files.len().div_ceil(MIN_FILES_PER_WORKER))
            .max(1);
        let write_chunk = |chunk: &[Named]| {
            chunk
                .iter()
                .try_for_each(|(name, bytes)| fs::write(directory.join(name), bytes))
        };
        if workers == 1 {
            return write_chunk(files);
        }
        thread::scope(|scope| {
            let handles: Vec<_> = files
                .chunks(files.len().div_ceil(workers))
                .map(|chunk| scope.spawn(move || write_chunk(chunk)))
                .collect();
            let mut first = Ok(());
            for handle in handles {
                let result = handle.join().unwrap_or_else(|panic| resume_unwind(panic));
                first = first.and(result);
            }
            first
        })
    }

    /// Creates `directory`, writes `files` into it a batch of `BATCH_SIZE` files at a time, and
    /// returns the files written.
    fn write_floor(directory: &Path, files: &[Named]) -> Outcome<u64> {
        fs::create_dir_all(directory)?;
        for batch in files.chunks(BATCH_SIZE) {
            write_batch(directory, batch)?;
        }
        Ok(u64::try_from(files.len())?)
    }

    /// The names of the files in `directory` but its manifest, in name order.
    fn file_names(directory: &Path) -> Outcome<Vec<String>> {
        Ok(read_eml_files(directory)?
            .into_iter()
            .map(|(name, _bytes)| name)
            .collect())
    }

    let raw = Arc::new(Pipeline::new(
        vec![Column::Raw, Column::Position],
        BATCH_SIZE,
    ));
    let defaults = Arc::new(Pipeline::new(Column::defaults(), BATCH_SIZE));
    let file = |name: &str| Destination::File(scratch.join(name));
    report("mbox", expected, || {
        export_pass(
            &raw,
            mailbox,
            file("export.mbox"),
            Box::new(MboxExporter::new()),
        )
    })?;
    report("eml", expected, || {
        let directory = Destination::Directory(scratch.join("eml"));
        let exporter = EmlExporter::new(mailbox.len());
        export_pass(&raw, mailbox, directory, Box::new(exporter))
    })?;
    let eml_directory = scratch.join("eml");
    let eml_files = read_eml_files(&eml_directory)?;
    let floor_directory = scratch.join("eml-floor");
    let floor = median_prepared(
        "eml-floor",
        expected,
        || match fs::remove_dir_all(&floor_directory) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error.into()),
            _ => Ok(()),
        },
        || write_floor(&floor_directory, &eml_files),
    )?;
    if file_names(&floor_directory)? != file_names(&eml_directory)? {
        return Err("eml-floor: its file set differs from the eml row's minus the manifest".into());
    }
    row("eml-floor", floor)?;
    report("jsonl", expected, || {
        export_pass(
            &defaults,
            mailbox,
            file("export.jsonl"),
            Box::new(JsonlExporter::new()),
        )
    })?;
    report("csv", expected, || {
        let exporter = CsvExporter::new(FormulaEscaping::Prefix);
        export_pass(&defaults, mailbox, file("export.csv"), Box::new(exporter))
    })?;
    report("ipc", expected, || {
        export_pass(
            &defaults,
            mailbox,
            file("export.arrows"),
            Box::new(IpcExporter::new()),
        )
    })?;
    // ab:new end
    Ok(())
}

/// Times the select, the Parquet exports, the copy and the sink exports over the fixture and
/// prints their rows.
fn main() -> Outcome<()> {
    let spec = common::Spec {
        messages: common::env_number("MBOXTURBO_BENCH_MESSAGES", DEFAULT_MESSAGES)?,
        seed: common::env_number("MBOXTURBO_BENCH_SEED", DEFAULT_SEED)?,
    };
    let directory = common::bench_directory()?;
    let path = common::ensure_fixture(&directory, &spec)?;
    let mailbox = Arc::new(Mailbox::open(&path)?);
    let pipeline = Arc::new(Pipeline::new(Column::defaults(), BATCH_SIZE));
    let scratch = tempfile::tempdir_in(&directory)?;
    let target = scratch.path().join("export.parquet");
    let copy = scratch.path().join("copy.mbox");
    let mailbox_bytes = fs::metadata(&path)?.len();
    let expected = u64::try_from(mailbox.len())?;
    writeln!(io::stdout().lock(), "messages {expected}")?;
    report("select", expected, || api::select_pass(&pipeline, &mailbox))?;
    report("parquet", expected, || {
        api::parquet_pass(&pipeline, &mailbox, &target, Compression::default())
    })?;
    if let Some(raw) = api::raw_pipeline(BATCH_SIZE) {
        report("raw-parquet", expected, || {
            api::parquet_pass(&raw, &mailbox, &target, Compression::default())
        })?;
        report("raw-parquet-uncompressed", expected, || {
            api::parquet_pass(&raw, &mailbox, &target, Compression::Uncompressed)
        })?;
    }
    report("copy", mailbox_bytes, || Ok(fs::copy(&path, &copy)?))?;
    sink_rows(&mailbox, scratch.path(), expected)
}
