//! Harness-free timings of the default column select and of the Parquet export over the
//! synthetic fixture the index bench uses.
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

use std::env::{self, VarError};
use std::error::Error;
use std::fs;
use std::hint::black_box;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

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

/// Passes every batch of the default columns through the reader and returns the rows seen.
fn select_pass(pipeline: &Arc<Pipeline>, mailbox: &Arc<Mailbox>) -> Outcome<usize> {
    let mut rows = 0_usize;
    for batch in pipeline.reader(mailbox) {
        rows = rows.saturating_add(black_box(batch?).num_rows());
    }
    Ok(rows)
}

/// Writes every message's default columns to a Parquet file at `path` and returns the rows
/// written.
fn parquet_pass(pipeline: &Arc<Pipeline>, mailbox: &Arc<Mailbox>, path: &Path) -> Outcome<u64> {
    Ok(pipeline.write_parquet(mailbox, path, Compression::default())?)
}

/// Times `RUNS` calls of `pass`, keeping each result alive, and returns the median.
fn median<T>(mut pass: impl FnMut() -> Outcome<T>) -> Outcome<Duration> {
    let mut runs = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        let start = Instant::now();
        let _kept = black_box(pass()?);
        runs.push(start.elapsed());
    }
    runs.sort_unstable();
    Ok(runs.get(MEDIAN_RUN).copied().unwrap_or(Duration::ZERO))
}

/// Prints one row: the median pass in milliseconds.
fn row(name: &str, elapsed: Duration) -> Outcome<()> {
    writeln!(
        io::stdout().lock(),
        "{name:<14} {:>10} ms",
        elapsed.as_millis()
    )?;
    Ok(())
}

/// Times the select and the Parquet export over the fixture and prints their rows.
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
    writeln!(io::stdout().lock(), "messages {}", mailbox.len())?;
    row("select", median(|| select_pass(&pipeline, &mailbox))?)?;
    row(
        "parquet",
        median(|| parquet_pass(&pipeline, &mailbox, &target))?,
    )
}
