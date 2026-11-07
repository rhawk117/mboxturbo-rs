//! `Mailbox` and its iterators: wrappers that release the interpreter while Rust works.

use std::convert::identity;
use std::iter::successors;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

use pyo3::IntoPyObjectExt;
use pyo3::exceptions::{PyIndexError, PyOverflowError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PySlice, PyTuple};

use crate::errors::{closed, into_py_err};
use crate::message::Message;

type Shared = Arc<mboxturbo::Mailbox>;

#[derive(Debug)]
struct Slot(RwLock<Option<Shared>>);

impl Slot {
    fn get(&self) -> PyResult<Shared> {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(Arc::clone)
            .ok_or_else(closed)
    }

    fn clear(&self) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = None;
    }
}

#[derive(Debug)]
struct Cursor(AtomicUsize);

impl Cursor {
    const fn new() -> Self {
        Self(AtomicUsize::new(0))
    }

    fn advance(&self, step: usize) -> usize {
        self.0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |at| {
                Some(at.saturating_add(step))
            })
            .unwrap_or_else(identity)
    }

    fn position(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
}

/// An mbox file mapped read-only and indexed in parallel.
///
/// ``index`` names a cache file: it is reused while it matches the mailbox and rebuilt and
/// rewritten when it is missing or stale. The file must not be modified while the mailbox, or
/// any message taken from it, is alive. Parallel work uses a thread pool that does not survive
/// ``os.fork()``; use the ``forkserver`` or ``spawn`` start method for multiprocessing.
#[pyclass(frozen, module = "mboxturbo")]
#[derive(Debug)]
pub(crate) struct Mailbox {
    slot: Slot,
}

#[pymethods]
impl Mailbox {
    #[new]
    #[pyo3(signature = (path, *, index = None))]
    fn new(py: Python<'_>, path: PathBuf, index: Option<PathBuf>) -> PyResult<Self> {
        let opened = py.detach(move || {
            index.as_deref().map_or_else(
                || mboxturbo::Mailbox::open(&path),
                |cache| mboxturbo::Mailbox::open_cached(&path, cache),
            )
        });
        let mailbox = opened.map_err(|error| into_py_err(py, error))?;
        Ok(Self {
            slot: Slot(RwLock::new(Some(Arc::new(mailbox)))),
        })
    }

    fn __len__(&self) -> PyResult<usize> {
        Ok(self.slot.get()?.len())
    }

    fn __getitem__(&self, py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        let mailbox = self.slot.get()?;
        if let Ok(slice) = key.cast::<PySlice>() {
            return select(&mailbox, slice)?.into_py_any(py);
        }
        let position = key
            .extract::<isize>()
            .map_err(|error| overflow_as_out_of_range(py, error))?;
        let message = resolve(position, mailbox.len())
            .and_then(|resolved| mailbox.message(resolved))
            .ok_or_else(out_of_range)?;
        Message::from(message).into_py_any(py)
    }

    fn __iter__(&self) -> PyResult<MessageIterator> {
        Ok(MessageIterator {
            mailbox: self.slot.get()?,
            cursor: Cursor::new(),
        })
    }

    /// Yields lists of up to ``size`` messages whose bodies and attachments are already decoded,
    /// in parallel in Rust, while the next batch is read ahead. For passes that read only
    /// header fields, plain iteration is faster: it never decodes bodies.
    fn batches(&self, size: usize) -> PyResult<BatchIterator> {
        if size == 0 {
            return Err(PyValueError::new_err("batch size must be positive"));
        }
        Ok(BatchIterator {
            mailbox: self.slot.get()?,
            size,
            cursor: Cursor::new(),
        })
    }

    /// Writes the message index to ``path`` atomically.
    fn save_index(&self, py: Python<'_>, path: PathBuf) -> PyResult<()> {
        let mailbox = self.slot.get()?;
        py.detach(move || mailbox.index().save(&path))
            .map_err(|error| into_py_err(py, error))
    }

    /// Releases this handle's mapping. Messages and iterators already taken keep it alive.
    fn close(&self) {
        self.slot.clear();
    }

    const fn __enter__(slf: Bound<'_, Self>) -> Bound<'_, Self> {
        slf
    }

    #[pyo3(signature = (*_exc_info))]
    fn __exit__(&self, _exc_info: &Bound<'_, PyTuple>) {
        self.slot.clear();
    }

    fn __repr__(&self) -> String {
        self.slot.get().map_or_else(
            |_| "Mailbox(closed)".to_owned(),
            |mailbox| format!("Mailbox(messages={})", mailbox.len()),
        )
    }
}

/// Iterates messages in file order; safe to share between threads, each ``next`` claiming a
/// distinct message.
#[pyclass(frozen, module = "mboxturbo")]
#[derive(Debug)]
pub(crate) struct MessageIterator {
    mailbox: Shared,
    cursor: Cursor,
}

#[pymethods]
impl MessageIterator {
    const fn __iter__(slf: Bound<'_, Self>) -> Bound<'_, Self> {
        slf
    }

    fn __next__(&self) -> Option<Message> {
        self.mailbox
            .message(self.cursor.advance(1))
            .map(Message::from)
    }

    fn __length_hint__(&self) -> usize {
        self.mailbox.len().saturating_sub(self.cursor.position())
    }
}

/// Iterates lists of parsed messages; safe to share between threads, each ``next`` claiming a
/// distinct batch.
#[pyclass(frozen, module = "mboxturbo")]
#[derive(Debug)]
pub(crate) struct BatchIterator {
    mailbox: Shared,
    size: usize,
    cursor: Cursor,
}

#[pymethods]
impl BatchIterator {
    const fn __iter__(slf: Bound<'_, Self>) -> Bound<'_, Self> {
        slf
    }

    fn __next__(&self, py: Python<'_>) -> Option<Vec<Message>> {
        let start = self.cursor.advance(self.size);
        if start >= self.mailbox.len() {
            return None;
        }
        let end = start.saturating_add(self.size);
        let parsed = py.detach(|| {
            self.mailbox.prefetch(end..end.saturating_add(self.size));
            self.mailbox.parse_batch(start..end)
        });
        Some(parsed.into_iter().map(Message::from).collect())
    }
}

fn select(mailbox: &mboxturbo::Mailbox, slice: &Bound<'_, PySlice>) -> PyResult<Vec<Message>> {
    let selection = slice.indices(isize::try_from(mailbox.len())?)?;
    Ok(
        successors(Some(selection.start), |at| at.checked_add(selection.step))
            .take(selection.slicelength)
            .filter_map(|at| usize::try_from(at).ok())
            .filter_map(|at| mailbox.message(at))
            .map(Message::from)
            .collect(),
    )
}

fn out_of_range() -> PyErr {
    PyIndexError::new_err("mailbox index out of range")
}

fn overflow_as_out_of_range(py: Python<'_>, error: PyErr) -> PyErr {
    if error.is_instance_of::<PyOverflowError>(py) {
        return out_of_range();
    }
    error
}

fn resolve(position: isize, len: usize) -> Option<usize> {
    let from_end = isize::try_from(len)
        .ok()
        .and_then(|signed| signed.checked_add(position));
    let absolute = if position < 0 { from_end? } else { position };
    usize::try_from(absolute)
        .ok()
        .filter(|&resolved| resolved < len)
}
