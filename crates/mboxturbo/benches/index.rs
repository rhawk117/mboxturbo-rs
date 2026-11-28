//! Harness-free timings of the message index over the synthetic fixture.
//!
//! The fixture is generated under the target directory on the first run and reused while its
//! message count and seed match and its length equals the byte count recorded beside it.
//! `MBOXTURBO_BENCH_DIR` moves it, and `MBOXTURBO_BENCH_MESSAGES` and `MBOXTURBO_BENCH_SEED`
//! override the defaults of one million messages and seed 1.

mod common;

use std::fs;
use std::hint::black_box;
use std::io::{self, Write as _};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use common::Outcome;
use mboxturbo::{IndexBytes, IndexPolicy, Mailbox, MailboxBuilder};

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

/// Everything one run measures.
#[derive(Debug)]
struct Report {
    /// Time to build the index in memory, writing nothing beside the fixture.
    build: Duration,
    /// Size of the built index by section.
    index: IndexBytes,
    /// Size of the saved index file.
    index_file: u64,
    /// Time of the span lookups at the random-access positions, without message bytes.
    lookup: Duration,
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
    /// Time of one pass over the index's slices in order, without message bytes.
    sweep: Duration,
}

/// The splitmix64 step, enough of a PRNG to pick positions reproducibly.
const fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut mixed = *state;
    mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    mixed ^ (mixed >> 31)
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

/// The error for a position the index has no span for, which a valid fixture never produces.
fn missing_span(position: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("the index has no span for message {position}"),
    )
}

/// The first byte of the message at `position`, an error when the message is empty.
fn first_byte(raw: &[u8], position: usize) -> Outcome<u8> {
    raw.first().copied().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message {position} is empty"),
        )
        .into()
    })
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
            let raw = mailbox
                .raw(position)
                .ok_or_else(|| missing_span(position))?;
            sum = sum.wrapping_add(u64::from(first_byte(raw, position)?));
        }
        Ok(black_box(sum))
    })?;
    Ok(elapsed)
}

/// Times a pass over every message, reading each first byte.
fn sequential(mailbox: &Mailbox) -> Outcome<Duration> {
    let (_, elapsed) = timed(|| {
        let mut sum = 0_u64;
        for (position, raw) in mailbox.iter().enumerate() {
            sum = sum.wrapping_add(u64::from(first_byte(raw, position)?));
        }
        Ok(black_box(sum))
    })?;
    Ok(elapsed)
}

/// Times the span lookups at `random_access`'s positions, never reading message bytes.
fn index_lookup(mailbox: &Mailbox, seed: u64) -> Outcome<Duration> {
    let length = u64::try_from(mailbox.len())?;
    let mut state = seed;
    let (_, elapsed) = timed(|| {
        let mut sum = 0_usize;
        for _ in 0..RANDOM_READS {
            let position =
                usize::try_from(splitmix64(&mut state).checked_rem(length).unwrap_or(0))?;
            let span = mailbox
                .index()
                .span(position)
                .ok_or_else(|| missing_span(position))?;
            sum = sum.wrapping_add(span.len());
        }
        Ok(black_box(sum))
    })?;
    Ok(elapsed)
}

/// Times one pass over every message's span in order through the index, reading no message
/// bytes at all.
fn index_sweep(mailbox: &Mailbox) -> Outcome<Duration> {
    let (_, elapsed) = timed(|| {
        let mut sum = 0_usize;
        let index = mailbox.index();
        for position in 0..mailbox.len() {
            let span = index.span(position).ok_or_else(|| missing_span(position))?;
            sum = sum.wrapping_add(span.len());
        }
        Ok(black_box(sum))
    })?;
    Ok(elapsed)
}

/// Times every operation against the v1 index.
fn measure(spec: &common::Spec) -> Outcome<Report> {
    let path = common::ensure_fixture(&common::bench_directory()?, spec)?;
    let index_path = path.with_extension("index");
    let (mailbox, build) = timed(|| {
        Ok(MailboxBuilder::new()
            .index(IndexPolicy::Memory)
            .open(&path)?)
    })?;
    let ((), save) = timed(|| Ok(mailbox.index().save(&index_path)?))?;
    Ok(Report {
        build,
        index: mailbox.index().bytes(),
        index_file: fs::metadata(&index_path)?.len(),
        messages: u64::try_from(mailbox.len())?,
        opens: cached_opens(&path, &index_path)?,
        random: random_access(&mailbox, spec.seed)?,
        lookup: index_lookup(&mailbox, spec.seed)?,
        save,
        scan: sequential(&mailbox)?,
        sweep: index_sweep(&mailbox)?,
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
    row(&mut out, "index-lookup", report.lookup, RANDOM_READS)?;
    row(&mut out, "sequential", report.scan, messages)?;
    row(&mut out, "index-sweep", report.sweep, messages)?;
    print_sizes(&mut out, report)
}

/// Prints the index size rows, in bytes per message.
fn print_sizes(out: &mut impl io::Write, report: &Report) -> Outcome<()> {
    for (name, bytes) in [
        ("index starts", report.index.starts),
        ("index dates", report.index.dates),
        ("index file", report.index_file),
    ] {
        writeln!(
            out,
            "{name:<14} {} B/msg",
            bytes_per_message(bytes, report.messages)
        )?;
    }
    Ok(())
}

/// Runs every timing against the v1 index and prints the table.
fn main() -> Outcome<()> {
    let spec = common::Spec {
        messages: common::env_number("MBOXTURBO_BENCH_MESSAGES", DEFAULT_MESSAGES)?,
        seed: common::env_number("MBOXTURBO_BENCH_SEED", DEFAULT_SEED)?,
    };
    print(&measure(&spec)?)
}
