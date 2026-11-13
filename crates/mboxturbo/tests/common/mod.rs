//! Deterministic synthetic mbox generator shared by the integration tests and the bench.
//!
//! Message sizes follow a log-normal with a median near 8 KB and a mean near 10 KB; about one
//! message in ten thousand is a 256 KB to 4 MB outlier and about one in a hundred has no `Date:`
//! header. Dates advance with jitter and are written in a handful of zone offsets.

#![expect(
    clippy::redundant_pub_crate,
    reason = "contradicts rustc's unreachable_pub, which is the lint this workspace keeps"
)]
#![expect(
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    clippy::float_arithmetic,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "bounded generator arithmetic on its own PRNG draws and calendar fields, never on \
              input data"
)]

use std::f64::consts::TAU;
use std::fs::File;
use std::io::{self, BufWriter, Write as _};
use std::path::Path;

const MEDIAN_BYTES: f64 = 8_192.0;
const SIGMA: f64 = 0.668;
const MIN_BYTES: u64 = 300;
const OUTLIER_ONE_IN: u64 = 10_000;
const OUTLIER_MIN_BYTES: u64 = 256 * 1024;
const OUTLIER_SPAN_BYTES: u64 = 4 * 1024 * 1024 - OUTLIER_MIN_BYTES;
const UNDATED_ONE_IN: u64 = 100;
const FIRST_UNIX_SECONDS: u64 = 1_422_958_272;
const LINE_BYTES: usize = 72;
const JITTER_SECONDS: u64 = 120;

/// What to generate: `messages` messages from the PRNG stream started by `seed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Spec {
    /// Number of messages written.
    pub messages: u64,
    /// Seed of the splitmix64 stream; equal specs produce byte-identical files.
    pub seed: u64,
}

impl Default for Spec {
    fn default() -> Self {
        Self {
            messages: 10_000,
            seed: 1,
        }
    }
}

/// What [`generate`] wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Summary {
    /// File length in bytes.
    pub bytes: u64,
    /// Messages that carry a `Date:` header.
    pub dated: u64,
    /// Positions of the messages that carry a `Date:` header, in file order.
    pub dated_positions: Vec<u64>,
    /// Messages written, equal to the separator count a scan finds.
    pub messages: u64,
}

/// Calendar fields of a Unix timestamp, with English day and month abbreviations.
struct Civil {
    day: u64,
    hour: u64,
    minute: u64,
    month: &'static str,
    second: u64,
    weekday: &'static str,
    year: u64,
}

impl Civil {
    /// Splits Unix seconds into proleptic Gregorian fields (Hinnant's `civil_from_days`).
    fn from_unix(seconds: u64) -> Self {
        let days = seconds / 86_400;
        let shifted = days + 719_468;
        let era = shifted / 146_097;
        let day_of_era = shifted % 146_097;
        let year_of_era =
            (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let month_index = (5 * day_of_year + 2) / 153;
        let month = if month_index < 10 {
            month_index + 3
        } else {
            month_index - 9
        };
        let year = era * 400 + year_of_era + u64::from(month <= 2);
        Self {
            day: day_of_year - (153 * month_index + 2) / 5 + 1,
            hour: seconds % 86_400 / 3_600,
            minute: seconds % 3_600 / 60,
            month: month_name(month),
            second: seconds % 60,
            weekday: weekday_name((days + 4) % 7),
            year,
        }
    }
}

/// Splitmix64 pseudo-random stream; equal seeds give equal draws.
struct Rng {
    state: u64,
}

impl Rng {
    const fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }

    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    const fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut mixed = self.state;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^ (mixed >> 31)
    }

    /// A standard normal draw by the Box-Muller transform.
    fn normal(&mut self) -> f64 {
        let radius = (-2.0 * self.unit().ln()).sqrt();
        radius * (TAU * self.unit()).cos()
    }

    /// A uniform draw in (0, 1].
    fn unit(&mut self) -> f64 {
        let [first, second, third, fourth, ..] = self.next_u64().to_le_bytes();
        (f64::from(u32::from_le_bytes([first, second, third, fourth])) + 1.0) / 4_294_967_297.0
    }
}

/// A file name that encodes the spec, such as `synthetic-10000-1.mbox`.
/// A file name that encodes the spec, such as `synthetic-10000-1.mbox`.
pub(crate) fn file_name(spec: &Spec) -> String {
    format!("synthetic-{}-{}.mbox", spec.messages, spec.seed)
}

/// Writes the mailbox for `spec` to `path`, one message at a time through a buffered writer.
///
/// # Errors
///
/// Returns the I/O error from creating, writing or flushing the file.
pub(crate) fn generate(path: &Path, spec: &Spec) -> io::Result<Summary> {
    let mut out = BufWriter::new(File::create(path)?);
    let mut rng = Rng::new(spec.seed);
    let mut clock = FIRST_UNIX_SECONDS;
    let mut message = Vec::new();
    let mut summary = Summary {
        messages: 0,
        bytes: 0,
        dated: 0,
        dated_positions: Vec::new(),
    };
    for number in 0..spec.messages {
        clock = clock.saturating_add(60 + rng.below(600));
        let dated = rng.below(UNDATED_ONE_IN) != 0;
        let shown = clock.saturating_add(rng.below(JITTER_SECONDS + 1));
        message.clear();
        build_message(&mut message, &mut rng, number, dated.then_some(shown))?;
        out.write_all(&message)?;
        summary.messages = summary.messages.saturating_add(1);
        summary.dated = summary.dated.saturating_add(u64::from(dated));
        if dated {
            summary.dated_positions.push(number);
        }
        summary.bytes = summary
            .bytes
            .saturating_add(u64::try_from(message.len()).map_err(io::Error::other)?);
    }
    out.flush()?;
    Ok(summary)
}

fn build_message(
    out: &mut Vec<u8>,
    rng: &mut Rng,
    number: u64,
    utc: Option<u64>,
) -> io::Result<()> {
    let target = sample_size(rng);
    out.extend_from_slice(format!("From sender{number}@example.com {}\n", asctime(utc)).as_bytes());
    out.extend_from_slice(
        format!("From: Sender {number} <sender{number}@example.com>\n").as_bytes(),
    );
    out.extend_from_slice(b"To: reader@example.org\n");
    out.extend_from_slice(format!("Subject: synthetic message {number}\n").as_bytes());
    out.extend_from_slice(format!("Message-ID: <{number}@synthetic.example.com>\n").as_bytes());
    if let Some(seconds) = utc {
        let offset = zone(rng);
        out.extend_from_slice(format!("Date: {}\n", rfc2822(seconds, offset)).as_bytes());
    }
    out.push(b'\n');
    let body = usize::try_from(target)
        .map_err(io::Error::other)?
        .saturating_sub(out.len());
    push_body(out, rng, body);
    out.push(b'\n');
    Ok(())
}

const fn zone(rng: &mut Rng) -> i64 {
    match rng.below(5) {
        0 => 0,
        1 => -300,
        2 => 60,
        3 => 330,
        _ => -480,
    }
}

/// Appends about `bytes` bytes of lowercase filler lines, none of which can start with `From `.
fn push_body(out: &mut Vec<u8>, rng: &mut Rng, bytes: usize) {
    let end = out.len().saturating_add(bytes);
    while out.len() < end {
        let mut line = 0;
        while line < LINE_BYTES {
            for byte in rng.next_u64().to_le_bytes() {
                out.push(filler(byte));
            }
            line += 8;
        }
        out.push(b'\n');
    }
}

const fn filler(byte: u8) -> u8 {
    let value = byte % 32;
    if value < 26 { b'a' + value } else { b' ' }
}

/// Draws a message size in bytes: log-normal, with the occasional 256 KB to 4 MB outlier.
fn sample_size(rng: &mut Rng) -> u64 {
    if rng.below(OUTLIER_ONE_IN) == 0 {
        return OUTLIER_MIN_BYTES.saturating_add(rng.below(OUTLIER_SPAN_BYTES));
    }
    let size = MEDIAN_BYTES * (SIGMA * rng.normal()).exp();
    to_bytes(size).max(MIN_BYTES)
}

const fn to_bytes(size: f64) -> u64 {
    size as u64
}

/// `Tue Feb  3 10:11:12 2015`-style text for the separator line; undated messages get the epoch.
fn asctime(utc: Option<u64>) -> String {
    let civil = Civil::from_unix(utc.unwrap_or(0));
    format!(
        "{} {} {:2} {:02}:{:02}:{:02} {}",
        civil.weekday, civil.month, civil.day, civil.hour, civil.minute, civil.second, civil.year
    )
}

/// `Tue, 03 Feb 2015 10:11:12 +0000`-style header value for `utc` shown at `offset_minutes`.
fn rfc2822(utc: u64, offset_minutes: i64) -> String {
    let local = utc.saturating_add_signed(offset_minutes * 60);
    let civil = Civil::from_unix(local);
    let sign = if offset_minutes < 0 { '-' } else { '+' };
    let magnitude = offset_minutes.unsigned_abs();
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} {sign}{:02}{:02}",
        civil.weekday,
        civil.day,
        civil.month,
        civil.year,
        civil.hour,
        civil.minute,
        civil.second,
        magnitude / 60,
        magnitude % 60
    )
}

const fn weekday_name(index: u64) -> &'static str {
    match index {
        0 => "Sun",
        1 => "Mon",
        2 => "Tue",
        3 => "Wed",
        4 => "Thu",
        5 => "Fri",
        _ => "Sat",
    }
}

const fn month_name(month: u64) -> &'static str {
    match month {
        1 => "Jan",
        2 => "Feb",
        3 => "Mar",
        4 => "Apr",
        5 => "May",
        6 => "Jun",
        7 => "Jul",
        8 => "Aug",
        9 => "Sep",
        10 => "Oct",
        11 => "Nov",
        _ => "Dec",
    }
}
