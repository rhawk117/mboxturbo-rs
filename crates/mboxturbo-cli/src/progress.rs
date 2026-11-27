//! What `export` shows on standard error: the live progress bar, the summary line and the note
//! that the index was rebuilt.
//!
//! Whether the run is "styled" is decided once, from the terminal and the colour variables, by
//! [`Environment::styled`]; the same decision picks clap's colours and whether the bar is drawn.

use std::env;
use std::ffi::OsString;
use std::io::{self, IsTerminal as _, Write as _};
use std::path::Path;
use std::time::{Duration, Instant};

use mboxturbo::{ExportSummary, IndexOrigin};

use crate::events::{Counts, Throttle};

/// The least time between two redraws of the bar.
const REDRAW_INTERVAL: Duration = Duration::from_millis(250);
/// Returns the cursor to the line start and erases the line.
const CLEAR_LINE: &str = "\r\x1b[2K";

/// How much `export` says on standard error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Feedback {
    /// The summary line and the rebuild note, and a live bar.
    Live,
    /// Nothing but error lines (`--quiet`).
    Silent,
    /// The summary line and the rebuild note, with no bar and no escape codes.
    Summary,
}

impl Feedback {
    /// Whether the progress bar is drawn.
    pub(crate) const fn draws(self) -> bool {
        matches!(self, Self::Live)
    }

    /// Whether the summary line and the rebuild note are printed.
    pub(crate) const fn speaks(self) -> bool {
        !matches!(self, Self::Silent)
    }
}
/// The facts that decide whether output is styled.
#[derive(Debug, Default)]
pub(crate) struct Environment {
    /// `CLICOLOR`: `0` turns styling off.
    pub clicolor: Option<OsString>,
    /// `CLICOLOR_FORCE`: any non-empty value other than `0` turns styling on.
    pub clicolor_force: Option<OsString>,
    /// `NO_COLOR`: any non-empty value turns styling off.
    pub no_color: Option<OsString>,
    /// Whether standard error is a terminal.
    pub terminal: bool,
}

impl Environment {
    /// The environment of this process.
    pub(crate) fn from_process() -> Self {
        Self {
            clicolor: env::var_os("CLICOLOR"),
            clicolor_force: env::var_os("CLICOLOR_FORCE"),
            no_color: env::var_os("NO_COLOR"),
            terminal: io::stderr().is_terminal(),
        }
    }

    /// Whether output is styled: `NO_COLOR` wins, then a `CLICOLOR_FORCE` other than empty or `0`,
    /// then `CLICOLOR=0`, then whether standard error is a terminal.
    pub(crate) fn styled(&self) -> bool {
        if self
            .no_color
            .as_ref()
            .is_some_and(|value| !value.is_empty())
        {
            return false;
        }
        if self
            .clicolor_force
            .as_ref()
            .is_some_and(|value| !value.is_empty() && value != "0")
        {
            return true;
        }
        if self.clicolor.as_ref().is_some_and(|value| value == "0") {
            return false;
        }
        self.terminal
    }
}

/// A one-line progress bar redrawn in place.
#[derive(Debug)]
pub(crate) struct Bar<W: io::Write> {
    /// Where the line is drawn.
    out: W,
    /// When the export began; rate and ETA are measured from it.
    started: Instant,
    /// Keeps redraws from outrunning the eye.
    throttle: Throttle,
}

impl<W: io::Write> Bar<W> {
    /// Erases the bar line.
    ///
    /// # Errors
    ///
    /// The I/O error of writing to the output.
    pub(crate) fn clear(&mut self) -> io::Result<()> {
        write!(self.out, "{CLEAR_LINE}")?;
        self.out.flush()
    }

    /// A bar for an export that began at `started`.
    pub(crate) const fn new(out: W, started: Instant) -> Self {
        Self {
            out,
            started,
            throttle: Throttle::new(REDRAW_INTERVAL),
        }
    }

    /// Redraws the bar for `counts` at `now`, unless it was redrawn within the last interval.
    ///
    /// # Errors
    ///
    /// The I/O error of writing to the output.
    pub(crate) fn update(&mut self, counts: Counts, now: Instant) -> io::Result<()> {
        if !self.throttle.admit(now) {
            return Ok(());
        }
        let elapsed = now.saturating_duration_since(self.started);
        write!(self.out, "{CLEAR_LINE}{}", render(counts, elapsed))?;
        self.out.flush()
    }
}

/// The bar text for `counts` after `elapsed`: messages done of total, messages per second and the
/// time left at that rate; rate and ETA read `-` until a message and a millisecond have passed.
pub(crate) fn render(counts: Counts, elapsed: Duration) -> String {
    let millis = elapsed.as_millis();
    let done = u128::from(counts.messages);
    let remaining = u128::from(counts.total.saturating_sub(counts.messages));
    let rate = done.saturating_mul(1000).checked_div(millis);
    let eta = remaining
        .saturating_mul(millis)
        .checked_div(done)
        .map(|left| left.div_euclid(1000));
    let rate_text = rate.map_or_else(|| "-".to_owned(), |value| format!("{value} msg/s"));
    let eta_text = eta.map_or_else(|| "-".to_owned(), clock);
    format!(
        "{} / {} messages  {rate_text}  ETA {eta_text}",
        counts.messages, counts.total
    )
}

/// `seconds` as `42s`, `3m05s` or `1h02m`.
fn clock(seconds: u128) -> String {
    let minutes = seconds.div_euclid(60);
    if minutes == 0 {
        return format!("{seconds}s");
    }
    if minutes < 60 {
        return format!("{minutes}m{:02}s", seconds.rem_euclid(60));
    }
    format!("{}h{:02}m", minutes.div_euclid(60), minutes.rem_euclid(60))
}

/// The summary line of a finished export written to `path`, with the number of undated messages
/// the date bounds excluded when it is not zero.
pub(crate) fn summary_line(
    summary: &ExportSummary,
    path: &Path,
    excluded_undated: Option<usize>,
) -> String {
    let excluded = excluded_undated
        .filter(|&count| count > 0)
        .map_or_else(String::new, |count| format!(" ({count} undated excluded)"));
    format!(
        "exported {} messages, {} bytes to {} in {:.1}s{excluded}",
        summary.messages,
        summary.bytes,
        path.display(),
        summary.elapsed.as_secs_f64()
    )
}

/// Prints the note that the index was rebuilt, when `feedback` speaks and `origin` says so.
///
/// # Errors
///
/// The I/O error of writing to standard error.
pub(crate) fn note_origin(feedback: Feedback, origin: IndexOrigin) -> io::Result<()> {
    if feedback.speaks() && origin == IndexOrigin::Rebuilt {
        writeln!(io::stderr(), "mboxturbo: index rebuilt")?;
    }
    Ok(())
}

/// Prints the summary line of a finished export, when `feedback` speaks.
///
/// # Errors
///
/// The I/O error of writing to standard error.
pub(crate) fn print_summary(
    feedback: Feedback,
    summary: &ExportSummary,
    path: &Path,
    excluded_undated: Option<usize>,
) -> io::Result<()> {
    if !feedback.speaks() {
        return Ok(());
    }
    writeln!(
        io::stderr(),
        "{}",
        summary_line(summary, path, excluded_undated)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counts(messages: u64, total: u64) -> Counts {
        Counts {
            bytes: 0,
            messages,
            total,
        }
    }

    fn environment(no_color: &str, clicolor: &str, force: &str) -> Environment {
        let value = |text: &str| (!text.is_empty()).then(|| OsString::from(text));
        Environment {
            clicolor: value(clicolor),
            clicolor_force: value(force),
            no_color: value(no_color),
            terminal: false,
        }
    }

    fn on_terminal(environment: Environment) -> Environment {
        Environment {
            terminal: true,
            ..environment
        }
    }

    #[test]
    fn a_terminal_with_no_variables_is_styled_and_a_pipe_is_not() {
        assert!(
            on_terminal(environment("", "", "")).styled(),
            "a terminal is styled"
        );
        assert!(!environment("", "", "").styled(), "a pipe is plain");
    }

    #[test]
    fn a_non_empty_no_color_makes_a_terminal_plain_even_when_forced() {
        assert!(
            !on_terminal(environment("1", "", "")).styled(),
            "NO_COLOR=1 is plain"
        );
        assert!(
            !on_terminal(environment("1", "", "1")).styled(),
            "NO_COLOR beats CLICOLOR_FORCE"
        );
    }

    #[test]
    fn an_empty_no_color_is_ignored() {
        assert!(
            on_terminal(environment("", "", "")).styled(),
            "NO_COLOR= does not disable"
        );
    }

    #[test]
    fn clicolor_zero_makes_a_terminal_plain() {
        assert!(
            !on_terminal(environment("", "0", "")).styled(),
            "CLICOLOR=0 is plain"
        );
        assert!(
            on_terminal(environment("", "1", "")).styled(),
            "CLICOLOR=1 leaves a terminal styled"
        );
    }

    #[test]
    fn clicolor_force_one_styles_a_pipe_and_zero_does_not() {
        assert!(
            environment("", "", "1").styled(),
            "CLICOLOR_FORCE=1 forces styling"
        );
        assert!(
            !environment("", "", "0").styled(),
            "CLICOLOR_FORCE=0 does not force, unlike clap"
        );
        assert!(
            environment("", "0", "1").styled(),
            "CLICOLOR_FORCE beats CLICOLOR=0"
        );
    }

    #[test]
    fn the_bar_text_shows_done_of_total_rate_and_eta() {
        assert_eq!(
            render(counts(250, 1000), Duration::from_secs(5)),
            "250 / 1000 messages  50 msg/s  ETA 15s",
            "750 left at 50 per second"
        );
    }

    #[test]
    fn the_eta_reads_in_minutes_and_hours() {
        assert_eq!(
            render(counts(1, 181), Duration::from_secs(1)),
            "1 / 181 messages  1 msg/s  ETA 3m00s",
            "180 seconds left"
        );
        assert_eq!(
            render(counts(1, 3601), Duration::from_secs(1)),
            "1 / 3601 messages  1 msg/s  ETA 1h00m",
            "3600 seconds left"
        );
    }

    #[test]
    fn rate_and_eta_are_dashes_before_anything_is_measured() {
        assert_eq!(
            render(counts(0, 10), Duration::from_secs(2)),
            "0 / 10 messages  0 msg/s  ETA -",
            "no message done: no ETA"
        );
        assert_eq!(
            render(counts(5, 10), Duration::ZERO),
            "5 / 10 messages  -  ETA 0s",
            "no time passed: no rate"
        );
    }

    #[test]
    fn the_bar_redraws_in_place_at_most_four_times_a_second() {
        let base = Instant::now();
        let mut bar = Bar::new(Vec::new(), base);
        for millis in [0_u64, 100, 249, 250, 400] {
            let now = base
                .checked_add(Duration::from_millis(millis))
                .expect("a test instant stays in range");
            bar.update(counts(millis, 1000), now)
                .expect("a vector accepts writes");
        }
        let drawn = String::from_utf8(bar.out).expect("the bar writes UTF-8");
        assert_eq!(
            drawn.matches('\r').count(),
            2_usize,
            "only the 0 ms and 250 ms updates draw"
        );
        assert_eq!(
            drawn.rsplit('\r').next(),
            Some("\u{1b}[2K250 / 1000 messages  1000 msg/s  ETA 0s"),
            "the second draw shows the 250 ms counts"
        );
    }
}
