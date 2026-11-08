//! `Mailbox` and its iterators: wrappers that release the interpreter while Rust works.
#![expect(
    clippy::too_many_arguments,
    reason = "pyo3's generated wrapper for #[pymethods] takes the interpreter, the receiver and \
              the raw argument arrays as parameters; the lint fires at the macro call site, so an \
              expectation on the impl block is unfulfilled and it must stay at module scope; no \
              signature in this module has that many"
)]

use std::convert::identity;
use std::iter::successors;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

use pyo3::IntoPyObjectExt as _;
use pyo3::exceptions::{PyIndexError, PyOverflowError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PySlice, PyTuple};

use crate::errors::{closed, into_py_err};
use crate::export::{Selection, select_columns};
use crate::message::Message;

/// A mailbox mapping shared between a handle and the iterators and messages taken from it.
type Shared = Arc<mboxturbo::Mailbox>;

/// The mapping a handle owns, emptied by `close`; later readers get `ValueError`.
#[derive(Debug)]
struct Slot(RwLock<Option<Shared>>);

impl Slot {
    /// Drops this handle's reference; clearing twice is harmless.
    fn clear(&self) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// A new reference to the mapping, or `ValueError` once the handle is closed.
    fn get(&self) -> PyResult<Shared> {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(Arc::clone)
            .ok_or_else(closed)
    }
}

/// A position that threads advance atomically, so each claims a distinct range of messages.
#[derive(Debug)]
struct Cursor(AtomicUsize);

impl Cursor {
    /// Claims `step` positions and returns the first; the position saturates at `usize::MAX`.
    #[expect(
        clippy::disallowed_methods,
        reason = "the update closure always returns Some, so fetch_update never returns Err and \
                  both arms of the Result carry the previous position"
    )]
    fn advance(&self, step: usize) -> usize {
        self.0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |at| {
                Some(at.saturating_add(step))
            })
            .unwrap_or_else(identity)
    }

    /// A cursor at the first message.
    const fn new() -> Self {
        Self(AtomicUsize::new(0))
    }

    /// The position the next claim starts at.
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
    /// The mapping, or nothing once closed.
    slot: Slot,
}

#[pymethods]
impl Mailbox {
    /// Returns the mailbox itself so ``with`` closes it on exit.
    const fn __enter__(slf: Bound<'_, Self>) -> Bound<'_, Self> {
        slf
    }

    /// Closes the mailbox; never suppresses the exception in flight.
    #[pyo3(signature = (*_exc_info))]
    fn __exit__(&self, _exc_info: &Bound<'_, PyTuple>) {
        self.slot.clear();
    }

    /// The message at an integer position (negative counts from the end) or a list for a slice;
    /// ``IndexError`` when the position is out of range, ``ValueError`` once closed.
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

    /// A fresh iterator over every message; ``ValueError`` once closed.
    fn __iter__(&self) -> PyResult<MessageIterator> {
        Ok(MessageIterator {
            mailbox: self.slot.get()?,
            cursor: Cursor::new(),
        })
    }

    /// The number of messages; ``ValueError`` once closed.
    fn __len__(&self) -> PyResult<usize> {
        Ok(self.slot.get()?.len())
    }

    /// ``Mailbox(messages=N)``, or ``Mailbox(closed)`` once closed.
    fn __repr__(&self) -> String {
        self.slot.get().map_or_else(
            |_| "Mailbox(closed)".to_owned(),
            |mailbox| format!("Mailbox(messages={})", mailbox.len()),
        )
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

    /// Releases this handle's mapping. Messages and iterators already taken keep it alive.
    fn close(&self) {
        self.slot.clear();
    }

    /// Opens ``path``, reusing or rewriting the cache at ``index`` when one is given.
    #[new]
    #[pyo3(signature = (path, *, index = None))]
    fn new(py: Python<'_>, path: PathBuf, index: Option<PathBuf>) -> PyResult<Self> {
        let opened = py.detach(move || {
            index.as_deref().map_or_else(
                || mboxturbo::Mailbox::open(&path).map_err(Box::new),
                |cache| mboxturbo::Mailbox::open_cached(&path, cache).map_err(Box::new),
            )
        });
        let mailbox = opened.map_err(|error| into_py_err(py, *error))?;
        Ok(Self {
            slot: Slot(RwLock::new(Some(Arc::new(mailbox)))),
        })
    }

    /// Writes the message index to ``path`` atomically.
    fn save_index(&self, py: Python<'_>, path: PathBuf) -> PyResult<()> {
        let mailbox = self.slot.get()?;
        py.detach(move || mailbox.index().save(&path).map_err(Box::new))
            .map_err(|error| into_py_err(py, *error))
    }

    /// Selects columns for export; ``None`` selects every column that needs only headers.
    /// Name columns from the catalogue (``subject``, ``received``, ``attachment_sha256``…) or
    /// as ``header:<Name>`` for any header's raw values.
    #[pyo3(signature = (columns = None, *, batch_size = 8192))]
    fn select(&self, columns: Option<Vec<String>>, batch_size: usize) -> PyResult<Selection> {
        select_columns(self.slot.get()?, columns, batch_size)
    }
}

/// Iterates messages in file order; safe to share between threads, each ``next`` claiming a
/// distinct message.
#[pyclass(frozen, module = "mboxturbo")]
#[derive(Debug)]
pub(crate) struct MessageIterator {
    /// The next message to hand out.
    cursor: Cursor,
    /// The mapping the messages are read from.
    mailbox: Shared,
}

#[pymethods]
impl MessageIterator {
    /// Returns the iterator itself.
    const fn __iter__(slf: Bound<'_, Self>) -> Bound<'_, Self> {
        slf
    }

    /// The messages not yet claimed; a hint only, since other threads may claim concurrently.
    fn __length_hint__(&self) -> usize {
        self.mailbox.len().saturating_sub(self.cursor.position())
    }

    /// The next unclaimed message, or ``None`` (ending iteration) after the last.
    fn __next__(&self) -> Option<Message> {
        self.mailbox
            .message(self.cursor.advance(1))
            .map(Message::from)
    }
}

/// Iterates lists of parsed messages; safe to share between threads, each ``next`` claiming a
/// distinct batch.
#[pyclass(frozen, module = "mboxturbo")]
#[derive(Debug)]
pub(crate) struct BatchIterator {
    /// The first message of the next batch.
    cursor: Cursor,
    /// The mapping the batches are parsed from.
    mailbox: Shared,
    /// Messages per batch; always positive.
    size: usize,
}

#[pymethods]
impl BatchIterator {
    /// Returns the iterator itself.
    const fn __iter__(slf: Bound<'_, Self>) -> Bound<'_, Self> {
        slf
    }

    /// The next unclaimed batch, shorter at the end of the file, or ``None`` (ending iteration)
    /// once all are claimed. The interpreter is released while the batch is parsed.
    fn __next__(&self, py: Python<'_>) -> Option<Vec<Message>> {
        let start = self.cursor.advance(self.size);
        if start >= self.mailbox.len() {
            return None;
        }
        let end = start.saturating_add(self.size);
        let parsed = py.detach(|| {
            self.mailbox.prefetch(end..end.saturating_add(self.size));
            self.mailbox.parse_batch(start..end).messages
        });
        Some(parsed.into_iter().map(Message::from).collect())
    }
}

/// The messages a slice selects, in slice order.
#[expect(
    clippy::disallowed_methods,
    reason = "PySlice::indices clamps to 0..len and take(slicelength) stops at the last selected \
              index, so every index is non-negative and below len and none is dropped"
)]
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

/// The `IndexError` for a position outside the mailbox.
fn out_of_range() -> PyErr {
    PyIndexError::new_err("mailbox index out of range")
}

/// Maps a position too large for `isize` to `IndexError`, since no mailbox is that long;
/// any other conversion error passes through.
fn overflow_as_out_of_range(py: Python<'_>, error: PyErr) -> PyErr {
    if error.is_instance_of::<PyOverflowError>(py) {
        return out_of_range();
    }
    error
}

/// The absolute position `position` names in a mailbox of `len` messages, counting negative
/// positions from the end, or `None` when it falls outside `0..len`.
#[expect(
    clippy::disallowed_methods,
    reason = "None here means out of range, which the caller raises as IndexError: a len beyond \
              isize::MAX or a negative absolute position is exactly such a position"
)]
fn resolve(position: isize, len: usize) -> Option<usize> {
    let from_end = isize::try_from(len)
        .ok()
        .and_then(|signed| signed.checked_add(position));
    let absolute = if position < 0 { from_end? } else { position };
    usize::try_from(absolute)
        .ok()
        .filter(|&resolved| resolved < len)
}
