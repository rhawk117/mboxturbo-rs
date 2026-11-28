//! Column selections: streamed through the Arrow C stream interface or written to Parquet.
#![expect(
    clippy::too_many_arguments,
    reason = "pyo3's generated wrapper for #[pymethods] takes the interpreter, the receiver and \
              the raw argument arrays as parameters; the lint fires at the macro call site, so an \
              expectation on the impl block is unfulfilled and it must stay at module scope; no \
              signature in this module has that many"
)]

use std::panic::resume_unwind;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::thread;
use std::time::Duration;

use arrow_array::ffi_stream::FFI_ArrowArrayStream;
use mboxturbo::{
    Column, Compression, Destination, DestinationKind, Export, ExportSummary, Exporter, Filter,
    MboxTurboError, Narrowed, Narrowing, Overwrite, ParquetExporter, Pipeline, Progress,
};
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyCapsule, PyDateTime, PyDelta, PyDeltaAccess as _, PyTzInfo};

use crate::errors::into_py_err;
use crate::exporter::{Failure, PythonExporter};
use crate::predicates::{Predicate, Trust};

/// The longest the calling thread waits for an export before it checks for signals.
const SIGNAL_INTERVAL: Duration = Duration::from_millis(50);

/// How an export on the worker thread ended.
type Stopped = Result<ExportSummary, Box<MboxTurboError>>;

/// Stops a running export from another thread; share one between exports to stop them together.
#[pyclass(frozen, module = "mboxturbo", name = "CancelToken")]
#[derive(Debug, Default)]
pub(crate) struct CancelToken {
    /// The core token every export given this one watches.
    inner: mboxturbo::CancelToken,
}

#[pymethods]
impl CancelToken {
    /// Stops every export given this token after its current batch.
    fn cancel(&self) {
        self.inner.cancel();
    }

    /// Whether ``cancel`` has been called.
    #[getter]
    fn is_cancelled(&self) -> bool {
        self.inner.is_cancelled()
    }

    /// A token that has not been cancelled.
    #[new]
    fn new() -> Self {
        Self::default()
    }
}

/// The narrowing a ``select`` call asks for, converted from its Python arguments.
#[derive(Debug)]
pub(crate) struct Filters {
    /// The only positions that may be kept.
    positions: Option<Vec<usize>>,
    /// The predicate rows must satisfy.
    predicate: Option<mboxturbo::Predicate>,
    /// The inclusive lower bound of the index date, in unix seconds.
    since: Option<i64>,
    /// The trust set that decides verdicts and trusted flags.
    trust: Option<mboxturbo::TrustSet>,
    /// The exclusive upper bound of the index date, in unix seconds.
    until: Option<i64>,
}

/// Chosen columns over a mailbox. Any Arrow consumer reads it directly (``pyarrow.table``,
/// ``polars.DataFrame``, ``DuckDB``), and ``to_parquet`` writes it to a file. Each read extracts
/// afresh, in parallel, parsing only what the columns need.
#[pyclass(frozen, module = "mboxturbo")]
#[derive(Debug)]
pub(crate) struct Selection {
    /// Rows per batch; a Parquet row group holds sixteen batches.
    batch_size: usize,
    /// The undated messages the bounds excluded from the candidates.
    excluded_undated: usize,
    /// The mapping the columns are extracted from.
    mailbox: Arc<mboxturbo::Mailbox>,
    /// The number of rows every read yields.
    messages: usize,
    /// The column names, in selection order.
    names: Vec<String>,
    /// The extraction plan shared by every read.
    pipeline: Arc<Pipeline>,
    /// The rows every read visits.
    rows: mboxturbo::Selection,
}

impl Filters {
    /// The filter for the predicate given, decided with this trust set; `None` without one.
    fn built_filter(&self) -> Result<Option<Filter>, Box<MboxTurboError>> {
        let Some(predicate) = &self.predicate else {
            return Ok(None);
        };
        let filter = Filter::new(predicate)?;
        Ok(Some(
            self.trust
                .clone()
                .into_iter()
                .fold(filter, Filter::with_trust),
        ))
    }

    /// Converts the Python arguments: `TypeError` for a naive `since` or `until`.
    pub(crate) fn from_python(
        py: Python<'_>,
        positions: Option<Vec<usize>>,
        since: Option<&Bound<'_, PyDateTime>>,
        until: Option<&Bound<'_, PyDateTime>>,
        predicate: Option<&Predicate>,
        trust: Option<&Trust>,
    ) -> PyResult<Self> {
        Ok(Self {
            positions,
            predicate: predicate.map(|wrapped| wrapped.predicate().clone()),
            since: since
                .map(|moment| unix_seconds(py, moment, "since"))
                .transpose()?,
            trust: trust.map(|wrapped| wrapped.trust_set().clone()),
            until: until
                .map(|moment| unix_seconds(py, moment, "until"))
                .transpose()?,
        })
    }

    /// The rows kept by every filter given, ascending and without repeats, or every row when
    /// none is given.
    fn pick(
        &self,
        mailbox: &mboxturbo::Mailbox,
        filter: Option<&Filter>,
    ) -> Result<Narrowed, Box<MboxTurboError>> {
        let mut narrowing = Narrowing::new().dates(self.since, self.until);
        if let Some(positions) = &self.positions {
            narrowing = narrowing.positions(positions.clone());
        }
        if let Some(found) = filter {
            narrowing = narrowing.filter(found);
        }
        Ok(narrowing.select(mailbox, None)?)
    }
}

#[pymethods]
impl Selection {
    /// Arrow C stream capsule over the selection; ``requested_schema`` is accepted and ignored.
    #[pyo3(signature = (requested_schema = None))]
    fn __arrow_c_stream__<'py>(
        &self,
        py: Python<'py>,
        requested_schema: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyCapsule>> {
        drop(requested_schema);
        let reader = self
            .pipeline
            .select(&self.mailbox, self.rows.clone())
            .map_err(|error| into_py_err(py, error))?;
        let stream = FFI_ArrowArrayStream::new(Box::new(reader));
        PyCapsule::new_with_value(py, stream, c"arrow_array_stream")
    }

    /// ``Selection(columns=N, messages=M)``, counting the rows the selection keeps.
    fn __repr__(&self) -> String {
        format!(
            "Selection(columns={}, messages={})",
            self.names.len(),
            self.messages
        )
    }

    /// Names of the selected columns, in order.
    #[getter]
    fn columns(&self) -> Vec<String> {
        self.names.clone()
    }

    /// The undated messages the bounds excluded from the ``positions`` given, or from the whole
    /// mailbox without ``positions``; 0 without ``since`` or ``until``.
    #[getter]
    const fn excluded_undated(&self) -> usize {
        self.excluded_undated
    }

    /// Writes the selection through ``exporter``, a Python object with ``begin(schema, out)``,
    /// ``write_batch(batch, out)`` and ``finish(out)``, and returns the row count. Its optional
    /// ``kind`` is ``'file'`` (default) or ``'directory'``. ``schema`` and ``batch`` expose the
    /// Arrow `PyCapsule` interface; ``out`` has ``write(data)`` for a file and is the staging
    /// ``pathlib.Path`` for a directory. Nothing lands at ``path`` unless ``finish`` succeeds.
    /// An exception from the exporter is raised as is, after the staged output is discarded.
    /// Overwrite, ``progress``, ``cancel`` and Ctrl-C behave as in ``to_parquet``. A directory
    /// destination is replaced with ``overwrite=True`` only when it is empty or holds a
    /// ``manifest.jsonl`` written by an earlier export. Any other existing directory, and any
    /// target of the other kind, raises ``FileExistsError`` and is left unchanged.
    #[pyo3(signature = (exporter, path, *, overwrite = false, progress = None, cancel = None))]
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "Python's `overwrite=` keyword is a bool by the requested interface"
    )]
    fn export(
        &self,
        py: Python<'_>,
        exporter: &Bound<'_, PyAny>,
        path: PathBuf,
        overwrite: bool,
        progress: Option<Py<PyAny>>,
        cancel: Option<&CancelToken>,
    ) -> PyResult<u64> {
        let kind = PythonExporter::declared_kind(exporter)?;
        let destination = if kind == DestinationKind::Directory {
            Destination::Directory(path)
        } else {
            Destination::File(path)
        };
        let failure = Arc::new(Failure::default());
        let sink = PythonExporter::new(exporter.clone().unbind(), kind, Arc::clone(&failure));
        let export = prepare(self, destination, overwrite_policy(overwrite));
        let result = run_export(py, export, Box::new(sink), progress, cancel);
        failure
            .take()
            .map_or_else(|| result.map(|summary| summary.messages), Err)
    }

    /// Writes the selection to a Parquet file at ``path`` atomically and returns the row count.
    /// An existing file raises ``FileExistsError`` and is left untouched unless ``overwrite`` is
    /// true. Even then, a directory at ``path`` is not replaced: ``overwrite`` does not replace
    /// an unrelated directory or a target of the other kind, and ``FileExistsError`` is raised.
    /// The GIL is released while exporting. ``progress(done, total)`` runs after each
    /// written batch. Ctrl-C, ``cancel``, or a ``progress`` that raises stops the export, leaves
    /// no file and raises ``Cancelled`` caused by the interrupt or the callback's exception.
    #[pyo3(signature = (
        path, *, compression = "zstd", overwrite = false, progress = None, cancel = None
    ))]
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "Python's `overwrite=` keyword is a bool by the requested interface"
    )]
    fn to_parquet(
        &self,
        py: Python<'_>,
        path: PathBuf,
        compression: &str,
        overwrite: bool,
        progress: Option<Py<PyAny>>,
        cancel: Option<&CancelToken>,
    ) -> PyResult<u64> {
        let codec = parse_compression(compression)?;
        let sink = ParquetExporter::new(codec).with_row_group_batches(self.batch_size);
        let export = prepare(self, Destination::File(path), overwrite_policy(overwrite));
        run_export(py, export, Box::new(sink), progress, cancel).map(|summary| summary.messages)
    }
}

/// The policy for an existing target: replaced when `overwrite` is true, refused otherwise.
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "Python's `overwrite=` keyword is a bool by the requested interface"
)]
const fn overwrite_policy(overwrite: bool) -> Overwrite {
    if overwrite {
        Overwrite::Replace
    } else {
        Overwrite::Refuse
    }
}

/// An export of `selection` to `destination` that handles an existing target as `policy` says.
fn prepare(selection: &Selection, destination: Destination, policy: Overwrite) -> Export {
    Export::new(
        Arc::clone(&selection.pipeline),
        Arc::clone(&selection.mailbox),
        destination,
    )
    .overwrite(policy)
    .selection(selection.rows.clone())
}

/// Runs `export` through `sink` on a worker thread with the interpreter released, while this
/// thread checks for signals. `progress(done, total)` runs after each batch. An interrupt, a
/// raising callback or a cancelled `cancel` stops the export through the core token, and the
/// stopped export raises `Cancelled` caused by the interrupt or the callback's exception.
pub(crate) fn run_export(
    py: Python<'_>,
    export: Export,
    sink: Box<dyn Exporter>,
    progress: Option<Py<PyAny>>,
    cancel: Option<&CancelToken>,
) -> PyResult<ExportSummary> {
    let token = cancel.map_or_else(mboxturbo::CancelToken::new, |wrapped| wrapped.inner.clone());
    let (raised_sender, raised) = mpsc::channel::<PyErr>();
    let watched = export.cancel_token(token.clone());
    let armed = match progress {
        Some(callback) => {
            let stop = token.clone();
            watched.on_progress(move |report| {
                report_progress(&callback, &stop, &raised_sender, report);
            })
        },
        None => watched,
    };
    let (result, interrupt) = run_on_worker(py, armed, sink, &token);
    match (result, raised.try_iter().next().or(interrupt)) {
        (Ok(summary), None) => Ok(summary),
        (Ok(_finished_first), Some(cause)) => Err(cause),
        (Err(error), cause) => {
            let stopped = into_py_err(py, *error);
            stopped.set_cause(py, cause);
            Err(stopped)
        },
    }
}

/// Runs `export` on a worker thread while the calling thread, with the interpreter released,
/// checks for signals every `SIGNAL_INTERVAL`; a signal that raises cancels `token` and is
/// returned beside the export's result once the worker has stopped.
fn run_on_worker(
    py: Python<'_>,
    export: Export,
    sink: Box<dyn Exporter>,
    token: &mboxturbo::CancelToken,
) -> (Stopped, Option<PyErr>) {
    let done = Arc::new(AtomicBool::new(false));
    let caller = thread::current();
    let worker = thread::spawn({
        let flag = Arc::clone(&done);
        move || {
            let result = export.run(sink).map_err(Box::new);
            flag.store(true, Ordering::Release);
            caller.unpark();
            result
        }
    });
    let mut interrupt = None;
    while !done.load(Ordering::Acquire) {
        py.detach(|| thread::park_timeout(SIGNAL_INTERVAL));
        if interrupt.is_none()
            && let Err(signal) = py.check_signals()
        {
            token.cancel();
            interrupt = Some(signal);
        }
    }
    let result = py
        .detach(move || worker.join())
        .unwrap_or_else(|payload| resume_unwind(payload));
    (result, interrupt)
}

/// Calls `callback(done, total)` with the GIL held; an exception cancels the export through
/// `token` and is passed to `raised` to become the cause of `Cancelled`.
fn report_progress(
    callback: &Py<PyAny>,
    token: &mboxturbo::CancelToken,
    raised: &Sender<PyErr>,
    report: Progress,
) {
    if token.is_cancelled() {
        return;
    }
    Python::attach(|py| {
        if let Err(error) = callback.call1(py, (report.messages, report.total)) {
            token.cancel();
            if let Err(lost) = raised.send(error) {
                lost.0.write_unraisable(py, None);
            }
        }
    });
}

/// The catalogue column names in order: the defaults when `opt_in` is false, the opt-in columns
/// when it is true, and every named column when it is `None`.
#[pyfunction]
#[pyo3(signature = (opt_in=None))]
pub(crate) fn column_names(opt_in: Option<bool>) -> Vec<String> {
    let columns = match opt_in {
        Some(false) => Column::defaults(),
        _ => Column::names().filter_map(Column::from_name).collect(),
    };
    columns
        .iter()
        .filter(|column| opt_in != Some(true) || column.is_opt_in())
        .map(|column| column.name().into_owned())
        .collect()
}

/// A selection over the rows `filters` keep in `mailbox`, with the interpreter released while
/// they are found; `ValueError` for a zero `batch_size` or an unknown column, with every column
/// in `Column::defaults` when `requested` is `None`.
pub(crate) fn select_columns(
    py: Python<'_>,
    mailbox: Arc<mboxturbo::Mailbox>,
    requested: Option<Vec<String>>,
    batch_size: usize,
    filters: &Filters,
) -> PyResult<Selection> {
    if batch_size == 0 {
        return Err(PyValueError::new_err("batch size must be positive"));
    }
    let columns =
        requested.map_or_else(|| Ok(Column::defaults()), |names| parse_columns(&names))?;
    let names = columns
        .iter()
        .map(|column| column.name().into_owned())
        .collect();
    let filter = filters
        .built_filter()
        .map_err(|error| into_py_err(py, *error))?;
    let rows = py
        .detach(|| filters.pick(&mailbox, filter.as_ref()))
        .map_err(|error| into_py_err(py, *error))?;
    let extraction = filters
        .trust
        .clone()
        .into_iter()
        .fold(Pipeline::new(columns, batch_size), Pipeline::with_trust);
    Ok(Selection {
        batch_size,
        excluded_undated: rows.excluded_undated.unwrap_or(0),
        mailbox,
        messages: rows.count,
        names,
        pipeline: Arc::new(extraction),
        rows: rows.selection,
    })
}

/// The columns `names` name, or `ValueError` listing the known names for the first unknown one.
fn parse_columns(names: &[String]) -> PyResult<Vec<Column>> {
    names
        .iter()
        .map(|name| {
            Column::from_name(name).ok_or_else(|| {
                let known = Column::names().collect::<Vec<_>>().join(", ");
                PyValueError::new_err(format!(
                    "unknown column '{name}'; expected one of {known}, or header:<Name>"
                ))
            })
        })
        .collect()
}

/// The codec `name` names (`zstd`, `snappy` or `none`), or `ValueError` for anything else.
fn parse_compression(name: &str) -> PyResult<Compression> {
    match name {
        "zstd" => Ok(Compression::Zstd),
        "snappy" => Ok(Compression::Snappy),
        "none" => Ok(Compression::Uncompressed),
        _ => Err(PyValueError::new_err(format!(
            "unknown compression '{name}'; expected 'zstd', 'snappy' or 'none'"
        ))),
    }
}

/// Unix seconds of an aware `moment`, rounded up when it has a fraction so that the whole
/// seconds at or after it are exactly those the instant admits; `TypeError` when it is naive.
fn unix_seconds(py: Python<'_>, moment: &Bound<'_, PyDateTime>, name: &str) -> PyResult<i64> {
    if moment.call_method0("utcoffset")?.is_none() {
        return Err(PyTypeError::new_err(format!(
            "{name} must be timezone-aware: give the datetime a tzinfo"
        )));
    }
    let epoch = PyDateTime::from_timestamp(py, 0.0, Some(&PyTzInfo::utc(py)?.to_owned()))?;
    let elapsed = moment.sub(epoch)?.cast_into::<PyDelta>()?;
    let whole = i64::from(elapsed.get_days())
        .saturating_mul(86_400)
        .saturating_add(i64::from(elapsed.get_seconds()));
    Ok(whole.saturating_add(i64::from(elapsed.get_microseconds() > 0)))
}
