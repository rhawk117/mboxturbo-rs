//! Harness-free timings of the default column select, of the Parquet export, of a raw-only
//! Parquet export and of a plain copy of the mailbox, over the synthetic fixture the index bench
//! uses. The raw-only export is held to three times the copy.
//!
//! The fixture is the index bench's: `MBOXTURBO_BENCH_DIR` moves it, and
//! `MBOXTURBO_BENCH_MESSAGES` and `MBOXTURBO_BENCH_SEED` override its defaults of one million
//! messages and seed 1. Each row is the median of `RUNS` passes, in milliseconds per pass.

#[path = "../tests/common/mod.rs"]
#[expect(
    clippy::missing_docs_in_private_items,
    reason = "the generator is shared with the integration tests, where the lint does not reach it"
)]
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

    /// Writes every message's default columns to a Parquet file at `path` and returns the rows
    /// written.
    pub(crate) fn parquet_pass(
        pipeline: &Arc<Pipeline>,
        mailbox: &Arc<Mailbox>,
        path: &Path,
    ) -> Outcome<u64> {
        let destination = Destination::File(path.to_path_buf());
        let summary = Export::new(Arc::clone(pipeline), Arc::clone(mailbox), destination)
            .overwrite(Overwrite::Replace)
            .run(Box::new(ParquetExporter::new(Compression::default())))?;
        Ok(summary.messages)
    }
}
// ab:api end

use std::env::{self, VarError};
use std::error::Error;
use std::fs;
use std::hint::black_box;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use mboxturbo::{Column, Mailbox, Pipeline};

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

/// Result of a bench step.
type Outcome<T> = Result<T, Box<dyn Error>>;

/// Reads `name` as a number, or `default` when it is unset.
fn env_number(name: &str, default: u64) -> Outcome<u64> {
    match env::var(name) {
        Ok(text) => Ok(text.parse()?),
        Err(VarError::NotPresent) => Ok(default),
        Err(error) => Err(error.into()),
    }
}

/// Directory holding the fixture and the temporary export.
fn bench_directory() -> Outcome<PathBuf> {
    match env::var_os("MBOXTURBO_BENCH_DIR") {
        Some(directory) => Ok(directory.into()),
        None => match env::var_os("CARGO_TARGET_DIR") {
            Some(directory) => Ok(directory.into()),
            None => Ok(PathBuf::from(env::var("CARGO_MANIFEST_DIR")?)
                .join("..")
                .join("..")
                .join("target")),
        },
    }
}

/// `path` with `suffix` appended to its file name, in the same directory.
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// The byte count recorded beside the fixture at `path`, or `None` when no record exists or it is
/// not a number, which makes the fixture untrusted.
fn recorded_length(path: &Path) -> Outcome<Option<u64>> {
    match fs::read_to_string(sibling(path, ".len")) {
        Ok(text) => text
            .trim()
            .parse()
            .map_or_else(|_| Ok(None), |bytes| Ok(Some(bytes))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// The length of the fixture at `path` when it exists and matches its recorded byte count.
fn reusable_length(path: &Path) -> Outcome<Option<u64>> {
    let actual = match fs::metadata(path) {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    Ok((recorded_length(path)? == Some(actual)).then_some(actual))
}

/// Generates the fixture to a partial file and renames it to `path`, so a killed run leaves
/// nothing at `path`, then records its byte count beside it.
fn generate_atomically(path: &Path, spec: &common::Spec) -> Outcome<common::Summary> {
    let length_path = sibling(path, ".len");
    match fs::remove_file(&length_path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error.into()),
        _ => {},
    }
    let partial = sibling(path, ".partial");
    let summary = common::generate(&partial, spec)?;
    fs::rename(&partial, path)?;
    fs::write(&length_path, summary.bytes.to_string())?;
    Ok(summary)
}

/// The fixture path for `spec` under `directory`, generated unless one of its recorded length
/// already exists.
fn ensure_fixture(directory: &Path, spec: &common::Spec) -> Outcome<PathBuf> {
    fs::create_dir_all(directory)?;
    let path = directory.join(common::file_name(spec));
    if reusable_length(&path)?.is_none() {
        let summary = generate_atomically(&path, spec)?;
        writeln!(
            io::stdout().lock(),
            "generated {} ({} messages, {} bytes)",
            path.display(),
            summary.messages,
            summary.bytes
        )?;
    }
    Ok(path)
}

/// Times `RUNS` calls of `pass` and returns the median.
///
/// # Errors
///
/// Fails when a pass fails or reports a row count other than `expected`, so a pass that drops
/// batches cannot time faster unnoticed.
fn median(name: &str, expected: u64, mut pass: impl FnMut() -> Outcome<u64>) -> Outcome<Duration> {
    let mut runs = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
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
    writeln!(io::stdout().lock(), "{name:<14} {text:>12} ms")?;
    Ok(())
}

/// Times `pass` as `name` and prints its row.
fn report(name: &str, expected: u64, pass: impl FnMut() -> Outcome<u64>) -> Outcome<()> {
    row(name, median(name, expected, pass)?)
}

/// Times the select, the Parquet exports and the copy over the fixture and prints their rows.
fn main() -> Outcome<()> {
    let spec = common::Spec {
        messages: env_number("MBOXTURBO_BENCH_MESSAGES", DEFAULT_MESSAGES)?,
        seed: env_number("MBOXTURBO_BENCH_SEED", DEFAULT_SEED)?,
    };
    let directory = bench_directory()?;
    let path = ensure_fixture(&directory, &spec)?;
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
        api::parquet_pass(&pipeline, &mailbox, &target)
    })?;
    if let Some(raw) = api::raw_pipeline(BATCH_SIZE) {
        report("raw-parquet", expected, || {
            api::parquet_pass(&raw, &mailbox, &target)
        })?;
    }
    report("copy", mailbox_bytes, || Ok(fs::copy(&path, &copy)?))
}
