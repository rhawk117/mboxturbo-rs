//! Ordered hand-off of parallel work: jobs run on rayon threads and their results come back in
//! submission order, each as soon as it and every job before it has finished.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvError, TryRecvError, sync_channel};
use std::thread;

/// Jobs in flight on the rayon pool, whose results are read back in the order they were submitted.
///
/// Dropping the stream cancels the jobs that have not started yet; a job already running finishes
/// and its result is discarded. A job that panics aborts the process (`rayon::spawn` has no panic
/// handler here), so jobs must contain their own panics.
#[derive(Debug)]
pub(crate) struct Ordered<T> {
    /// Set on drop so queued jobs skip their work.
    cancelled: Arc<AtomicBool>,
    /// One receiver per submitted job, oldest first.
    pending: VecDeque<Receiver<T>>,
}

impl<T: Send + 'static> Ordered<T> {
    /// A stream with nothing in flight.
    pub(crate) fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            pending: VecDeque::new(),
        }
    }

    /// Number of submitted jobs whose result has not been taken yet.
    pub(crate) fn in_flight(&self) -> usize {
        self.pending.len()
    }

    /// Blocks until the oldest submitted job has finished and returns its result, or `None` when
    /// nothing is in flight.
    pub(crate) fn next(&mut self) -> Option<T> {
        let receiver = self.pending.pop_front()?;
        // A job sends nothing only when it was cancelled, and that happens only after this
        // stream is dropped.
        let Ok(result) = wait_for(&receiver) else {
            return None;
        };
        Some(result)
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
            // The channel holds one result, so the send never blocks; it fails only when the
            // stream was dropped, and then nobody wants the result.
            drop(sender.send(job()));
        });
        self.pending.push_back(receiver);
    }
}

/// Waits for the result on `receiver`. On a rayon worker thread the wait runs other queued jobs
/// instead of blocking, because the awaited job may sit in this very thread's queue.
fn wait_for<T>(receiver: &Receiver<T>) -> Result<T, RecvError> {
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

impl<T> Drop for Ordered<T> {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc::channel;
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
    fn dropping_the_stream_skips_jobs_that_have_not_started() {
        let pool = pool(1);
        let ran = Arc::new(AtomicUsize::new(0));
        let (release, released) = channel::<()>();
        let (started_sender, started) = channel::<()>();
        let mut stream = Ordered::new();
        let released = Arc::new(Mutex::new(released));
        pool.install(|| {
            for _ in 0..9 {
                let count = Arc::clone(&ran);
                let gate = Arc::clone(&released);
                let signal = started_sender.clone();
                stream.submit(move || {
                    let _previous = count.fetch_add(1, Ordering::SeqCst);
                    signal.send(()).expect("the test waits for the start");
                    gate.lock()
                        .expect("no job panics while holding the gate")
                        .recv_timeout(STUCK)
                        .expect("the test releases the running job after the drop");
                });
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
