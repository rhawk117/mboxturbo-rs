//! Harness-free timings of the message index over the synthetic fixture.
//!
//! The fixture is generated under the target directory on the first run and reused while its
//! message count and seed match. `MBOXTURBO_BENCH_DIR` moves it, and `MBOXTURBO_BENCH_MESSAGES`
//! and `MBOXTURBO_BENCH_SEED` override the defaults of one million messages and seed 1.

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
use std::path::PathBuf;
use std::time::{Duration, Instant};

use mboxturbo::Mailbox;

/// Messages in the fixture when `MBOXTURBO_BENCH_MESSAGES` is unset.
const DEFAULT_MESSAGES: u64 = 1_000_000;
/// Seed of the fixture when `MBOXTURBO_BENCH_SEED` is unset.
const DEFAULT_SEED: u64 = 1;
/// Position of the median in the sorted cached-open timings.
const MEDIAN_RUN: usize = 2;
/// Cached opens timed.
const OPEN_RUNS: usize = 5;
/// Positions read by the random-access row.
const RANDOM_READS: u64 = 100_000;

/// Result of a bench step.
type Outcome<T> = Result<T, Box<dyn Error>>;

/// Everything one run measures.
#[derive(Debug)]
struct Report {
    /// Time to build the index with `Mailbox::open`.
    build: Duration,
    /// Size of the saved index file.
    index_bytes: u64,
    /// Messages in the mailbox.
    messages: u64,
    /// Cached-open timings, sorted ascending.
    opens: Vec<Duration>,
    /// Time of the random-access reads.
    random: Duration,
    /// Time to write the index.
    save: Duration,
    /// Time of the sequential pass.
    scan: Duration,
}

/// The splitmix64 step, enough of a PRNG to pick positions reproducibly.
const fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut mixed = *state;
    mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    mixed ^ (mixed >> 31)
}

/// Reads `name` as a number, or `default` when it is unset.
fn env_number(name: &str, default: u64) -> Outcome<u64> {
    match env::var(name) {
        Ok(text) => Ok(text.parse()?),
        Err(VarError::NotPresent) => Ok(default),
        Err(error) => Err(error.into()),
    }
}

/// Directory holding the fixture and the saved index.
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

/// Times `work` and returns its result with the elapsed time.
fn timed<T>(work: impl FnOnce() -> Outcome<T>) -> Outcome<(T, Duration)> {
    let start = Instant::now();
    let value = work()?;
    Ok((value, start.elapsed()))
}

/// Nanoseconds per operation, zero when there were none.
fn per_operation(total: Duration, operations: u64) -> u128 {
    total
        .as_nanos()
        .checked_div(u128::from(operations))
        .unwrap_or(0)
}

/// Prints one timed row: the total in milliseconds and the figure per operation in nanoseconds.
fn row(out: &mut impl io::Write, name: &str, total: Duration, operations: u64) -> Outcome<()> {
    let each = per_operation(total, operations);
    writeln!(
        out,
        "{name:<14} {:>10} ms {each:>12} ns/op",
        total.as_millis()
    )?;
    Ok(())
}

/// Prints `bytes / messages` with two decimals, as integer arithmetic on hundredths.
fn bytes_per_message(bytes: u64, messages: u64) -> String {
    let hundredths = u128::from(bytes)
        .saturating_mul(100)
        .checked_div(u128::from(messages))
        .unwrap_or(0);
    format!(
        "{}.{:02}",
        hundredths.checked_div(100).unwrap_or(0),
        hundredths.checked_rem(100).unwrap_or(0)
    )
}

/// Generates the fixture at its derived path unless it already exists, and says which.
fn ensure_fixture(spec: &common::Spec) -> Outcome<PathBuf> {
    let directory = bench_directory()?;
    fs::create_dir_all(&directory)?;
    let path = directory.join(common::file_name(spec));
    let mut out = io::stdout().lock();
    if path.exists() {
        let bytes = fs::metadata(&path)?.len();
        writeln!(out, "reused {} ({bytes} bytes)", path.display())?;
    } else {
        let started = Instant::now();
        let summary = common::generate(&path, spec)?;
        writeln!(
            out,
            "generated {} ({} messages, {} dated, {} bytes) in {} ms",
            path.display(),
            summary.messages,
            summary.dated,
            summary.bytes,
            started.elapsed().as_millis()
        )?;
    }
    Ok(path)
}

/// Times `OPEN_RUNS` cached opens, sorted ascending.
fn cached_opens(path: &PathBuf, index_path: &PathBuf) -> Outcome<Vec<Duration>> {
    let mut runs = Vec::with_capacity(OPEN_RUNS);
    for _ in 0..OPEN_RUNS {
        let (mailbox, elapsed) = timed(|| Ok(Mailbox::open_cached(path, index_path)?))?;
        drop(black_box(mailbox));
        runs.push(elapsed);
    }
    runs.sort_unstable();
    Ok(runs)
}

/// Times `RANDOM_READS` reads of the first byte at seeded random positions.
fn random_access(mailbox: &Mailbox, seed: u64) -> Outcome<Duration> {
    let length = u64::try_from(mailbox.len())?;
    let mut state = seed;
    let (_, elapsed) = timed(|| {
        let mut sum = 0_u64;
        for _ in 0..RANDOM_READS {
            let position =
                usize::try_from(splitmix64(&mut state).checked_rem(length).unwrap_or(0))?;
            let first = mailbox.raw(position).and_then(|raw| raw.first().copied());
            sum = sum.wrapping_add(u64::from(first.unwrap_or(0)));
        }
        Ok(black_box(sum))
    })?;
    Ok(elapsed)
}

/// Times a pass over every message, reading each first byte.
fn sequential(mailbox: &Mailbox) -> Outcome<Duration> {
    let (_, elapsed) = timed(|| {
        let mut sum = 0_u64;
        for raw in mailbox.iter() {
            sum = sum.wrapping_add(u64::from(raw.first().copied().unwrap_or(0)));
        }
        Ok(black_box(sum))
    })?;
    Ok(elapsed)
}

/// Times every operation against the v1 index.
fn measure(spec: &common::Spec) -> Outcome<Report> {
    let path = ensure_fixture(spec)?;
    let index_path = path.with_extension("index");
    let (mailbox, build) = timed(|| Ok(Mailbox::open(&path)?))?;
    let ((), save) = timed(|| Ok(mailbox.index().save(&index_path)?))?;
    Ok(Report {
        build,
        index_bytes: fs::metadata(&index_path)?.len(),
        messages: u64::try_from(mailbox.len())?,
        opens: cached_opens(&path, &index_path)?,
        random: random_access(&mailbox, spec.seed)?,
        save,
        scan: sequential(&mailbox)?,
    })
}

/// Prints the table to stdout.
fn print(report: &Report) -> Outcome<()> {
    let mut out = io::stdout().lock();
    let messages = report.messages;
    writeln!(out, "messages {messages}")?;
    row(&mut out, "build", report.build, messages)?;
    row(&mut out, "save", report.save, messages)?;
    let best = report.opens.first().copied().unwrap_or(Duration::ZERO);
    let median = report
        .opens
        .get(MEDIAN_RUN)
        .copied()
        .unwrap_or(Duration::ZERO);
    writeln!(
        out,
        "{:<14} best {} us, median {} us (of {OPEN_RUNS})",
        "cached-open",
        best.as_micros(),
        median.as_micros()
    )?;
    row(&mut out, "random-access", report.random, RANDOM_READS)?;
    row(&mut out, "sequential", report.scan, messages)?;
    let starts = bytes_per_message(report.index_bytes, messages);
    writeln!(out, "{:<14} {starts} B/msg", "index starts")?;
    writeln!(out, "{:<14} n/a", "index dates")?;
    Ok(())
}

/// Runs every timing against the v1 index and prints the table.
fn main() -> Outcome<()> {
    let spec = common::Spec {
        messages: env_number("MBOXTURBO_BENCH_MESSAGES", DEFAULT_MESSAGES)?,
        seed: env_number("MBOXTURBO_BENCH_SEED", DEFAULT_SEED)?,
    };
    print(&measure(&spec)?)
}
