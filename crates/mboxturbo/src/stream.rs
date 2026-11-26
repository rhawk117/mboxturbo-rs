//! Ordered hand-off of parallel work: jobs run on rayon threads and their results come back in
//! submission order, each as soon as it and every job before it has finished.

use std::any::Any;
use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvError, TryRecvError, sync_channel};
use std::thread;

/// Jobs in flight on the rayon pool, whose results are read back in the order they were submitted.
///
/// Dropping the stream cancels the jobs that have not started yet; a job already running finishes
/// and its result is discarded. A job that panics does not abort the process: the panic is caught
/// on the pool thread and [`Ordered::next`] re-raises it on the reading thread.
#[derive(Debug)]
pub(crate) struct Ordered<T> {
    /// Set on drop so queued jobs skip their work.
    cancelled: Arc<AtomicBool>,
    /// One receiver per submitted job with its submission number, oldest first.
    pending: VecDeque<PendingJob<T>>,
    /// Number of jobs submitted so far.
    submitted: usize,
}

/// What a job sent back: its result, or the payload of the panic it raised.
type JobOutcome<T> = Result<T, Box<dyn Any + Send>>;

/// A submitted job's number and the receiver of its outcome.
type PendingJob<T> = (usize, Receiver<JobOutcome<T>>);

impl<T: Send + 'static> Ordered<T> {
    /// Number of submitted jobs whose result has not been taken yet.
    pub(crate) fn in_flight(&self) -> usize {
        self.pending.len()
    }

    /// A stream with nothing in flight.
    pub(crate) fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            pending: VecDeque::new(),
            submitted: 0,
        }
    }

    /// Blocks until the oldest submitted job has finished and returns its result, or `None` when
    /// nothing is in flight.
    ///
    /// # Panics
    ///
    /// Re-raises the panic of the job whose result is taken, on the calling thread. Also panics,
    /// naming the job, if that job ended without sending anything, which only a cancelled job
    /// does and cancellation happens only when the stream is dropped.
    #[expect(
        clippy::panic,
        reason = "a job that vanished without a result must not read as a shorter stream"
    )]
    pub(crate) fn next(&mut self) -> Option<T> {
        let (job, receiver) = self.pending.pop_front()?;
        match wait_for(&receiver) {
            Ok(Ok(result)) => Some(result),
            Ok(Err(payload)) => resume_unwind(payload),
            Err(RecvError) => panic!("extraction job {job} ended without sending a result"),
        }
    }

    /// Queues `job` on the rayon pool; its result is returned by a later [`Ordered::next`] after
    /// the results of every job submitted before it.
    pub(crate) fn submit<F>(&mut self, job: F)
    where
        F: FnOnce() -> T + Send + 'static,
    {
        let (sender, receiver) = sync_channel(1);
        let cancelled = Arc::clone(&self.cancelled);
        rayon::spawn(move || {
            if cancelled.load(Ordering::Relaxed) {
                return;
            }
            #[expect(
                clippy::disallowed_methods,
                reason = "rayon::spawn aborts on a panic; Ordered::next re-raises the payload"
            )]
            let outcome = catch_unwind(AssertUnwindSafe(job));
            // The channel holds one result, so the send never blocks; it fails only when the
            // stream was dropped, and then nobody wants the result.
            drop(sender.send(outcome));
        });
        self.pending.push_back((self.submitted, receiver));
        self.submitted = self.submitted.saturating_add(1);
    }
}

impl<T> Drop for Ordered<T> {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

/// Waits for the result on `receiver`. On a rayon worker thread the wait runs other queued jobs
/// instead of blocking, because the awaited job may sit in this very thread's queue.
fn wait_for<T>(receiver: &Receiver<JobOutcome<T>>) -> Result<JobOutcome<T>, RecvError> {
    if rayon::current_thread_index().is_none() {
        return receiver.recv();
    }
    loop {
        match receiver.try_recv() {
            Ok(result) => return Ok(result),
            Err(TryRecvError::Disconnected) => return Err(RecvError),
            Err(TryRecvError::Empty) => {
                if rayon::yield_now().is_none() {
                    thread::yield_now();
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::panic::panic_any;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc::{Sender, channel};
    use std::time::Duration;

    use super::*;

    /// A bound that only a broken implementation reaches: it turns a deadlock into a failure.
    const STUCK: Duration = Duration::from_secs(60);

    fn pool(threads: usize) -> rayon::ThreadPool {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .expect("test thread pool builds")
    }

    #[test]
    fn the_first_result_is_returned_while_a_later_job_is_still_running() {
        let pool = pool(2);
        let (release, released) = channel::<()>();
        let mut stream = Ordered::new();
        pool.install(|| {
            stream.submit(|| 0_u32);
            stream.submit(move || {
                released
                    .recv_timeout(STUCK)
                    .expect("the test releases the second job after reading the first result");
                1
            });
        });
        assert_eq!(
            stream.next(),
            Some(0),
            "the first result must not wait for the second job"
        );
        release.send(()).expect("the second job is still waiting");
        assert_eq!(stream.next(), Some(1), "results keep submission order");
        assert_eq!(stream.next(), None, "nothing is left in flight");
    }

    #[test]
    fn results_keep_submission_order_when_later_jobs_finish_first() {
        let pool = pool(2);
        let (release, released) = channel::<()>();
        let mut stream = Ordered::new();
        pool.install(|| {
            stream.submit(move || {
                released
                    .recv_timeout(STUCK)
                    .expect("the test releases the first job after the second finished");
                0_u32
            });
            stream.submit(|| 1);
        });
        release.send(()).expect("the first job is still waiting");
        assert_eq!(stream.next(), Some(0), "the older job is returned first");
        assert_eq!(stream.next(), Some(1), "the younger job follows");
    }

    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "the test observes the panic Ordered::next re-raises"
    )]
    fn a_job_panic_is_re_raised_by_next_and_the_stream_still_drops_cleanly() {
        let pool = pool(2);
        let mut stream = Ordered::new();
        pool.install(|| {
            stream.submit(|| 0_u32);
            stream.submit(|| -> u32 { panic_any("job two failed") });
            stream.submit(|| 2);
        });
        assert_eq!(
            stream.next(),
            Some(0),
            "the job before the panic is unaffected"
        );
        let payload = catch_unwind(AssertUnwindSafe(|| stream.next()))
            .expect_err("the panicking job's result re-raises on the reader");
        assert_eq!(
            payload.downcast_ref::<&str>(),
            Some(&"job two failed"),
            "the original payload is re-raised, not a wrapper"
        );
        assert_eq!(
            stream.next(),
            Some(2),
            "the job after the panic is still delivered"
        );
        drop(stream);
        pool.install(|| ());
    }

    /// A job that counts itself, announces its start and then waits, bounded, for `gate`.
    fn gated_job(
        ran: &Arc<AtomicUsize>,
        started: &Sender<()>,
        gate: &Arc<Mutex<Receiver<()>>>,
    ) -> impl FnOnce() + Send + 'static {
        let count = Arc::clone(ran);
        let signal = started.clone();
        let held = Arc::clone(gate);
        move || {
            let _previous = count.fetch_add(1, Ordering::SeqCst);
            signal.send(()).expect("the test waits for the start");
            held.lock()
                .expect("no job panics while holding the gate")
                .recv_timeout(STUCK)
                .expect("the test releases the running job after the drop");
        }
    }

    #[test]
    fn dropping_the_stream_skips_jobs_that_have_not_started() {
        let pool = pool(1);
        let ran = Arc::new(AtomicUsize::new(0));
        let (release, held) = channel::<()>();
        let (started_sender, started) = channel::<()>();
        let mut stream = Ordered::new();
        let gate = Arc::new(Mutex::new(held));
        pool.install(|| {
            for _ in 0..9_u8 {
                stream.submit(gated_job(&ran, &started_sender, &gate));
            }
        });
        started.recv_timeout(STUCK).expect("the first job starts");
        drop(stream);
        release.send(()).expect("the running job is still waiting");
        pool.install(|| ());
        assert_eq!(
            ran.load(Ordering::SeqCst),
            1,
            "only the job already running when the stream was dropped did any work"
        );
    }
}
