//! Turns termination signals into cancellation of the running export.
//!
//! The first signal cancels the export, which stops within one batch and removes what it staged;
//! the exit code then names the signal. A second signal ends the process at once with that
//! signal's code, so a stuck shutdown never needs `kill -9`.
//!
//! On Windows the CRT raises `SIGINT` for Ctrl-C and `SIGBREAK` for Ctrl-Break; both are handled
//! and exit 130, and `SIGTERM` exits 143.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::{io, thread};

use mboxturbo::CancelToken;
#[cfg(windows)]
use signal_hook::consts::signal::SIGBREAK;
#[cfg(unix)]
use signal_hook::consts::signal::SIGHUP;
use signal_hook::consts::signal::{SIGINT, SIGTERM};
use signal_hook::flag;

/// How often the watcher looks for an arrived signal; the delay before cancellation starts.
const POLL: Duration = Duration::from_millis(20);

/// The signals handled and the exit code of each: 128 plus the signal number.
#[cfg(unix)]
const HANDLED: [(i32, u8); 3] = [(SIGHUP, 129), (SIGINT, 130), (SIGTERM, 143)];

/// The signals handled and the exit code of each.
#[cfg(windows)]
const HANDLED: [(i32, u8); 3] = [(SIGINT, 130), (SIGBREAK, 130), (SIGTERM, 143)];

/// One handled signal: its exit code and whether it has arrived.
type Arrival = (u8, Arc<AtomicBool>);

/// Watches for the handled signals while an export runs.
#[derive(Debug)]
pub(crate) struct Interrupts {
    /// One entry per handled signal.
    arrivals: Vec<Arrival>,
}

impl Interrupts {
    /// The exit code of the first signal that arrived; `None` when none has.
    pub(crate) fn code(&self) -> Option<u8> {
        self.arrivals
            .iter()
            .find(|(_, arrived)| arrived.load(Ordering::Acquire))
            .map(|&(code, _)| code)
    }

    /// Handles the signals: the first one cancels `cancel`, a second one exits the process.
    ///
    /// # Errors
    ///
    /// The I/O error of registering a handler with the operating system.
    pub(crate) fn watch(cancel: CancelToken) -> io::Result<Self> {
        let armed = Arc::new(AtomicBool::new(false));
        let arrivals = HANDLED
            .iter()
            .map(|&(signal, code)| register(signal, code, &armed))
            .collect::<io::Result<Vec<_>>>()?;
        let watched = arrivals.clone();
        drop(thread::spawn(move || cancel_on_arrival(&watched, &cancel)));
        Ok(Self { arrivals })
    }
}

/// Registers the handlers for `signal`: exit with `code` when `armed` is already set, then set
/// `armed`, then set the signal's own flag. The order matters: the exit check must run first.
fn register(signal: i32, code: u8, armed: &Arc<AtomicBool>) -> io::Result<Arrival> {
    let own = Arc::new(AtomicBool::new(false));
    let _shutdown =
        flag::register_conditional_shutdown(signal, i32::from(code), Arc::clone(armed))?;
    let _arm = flag::register(signal, Arc::clone(armed))?;
    let _own = flag::register(signal, Arc::clone(&own))?;
    Ok((code, own))
}

/// Waits until one of `arrivals` is set, then cancels the export.
fn cancel_on_arrival(arrivals: &[Arrival], cancel: &CancelToken) {
    while !arrivals
        .iter()
        .any(|(_, arrived)| arrived.load(Ordering::Acquire))
    {
        thread::sleep(POLL);
    }
    cancel.cancel();
}
