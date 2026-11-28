//! Python-written exporters: an [`Exporter`] that hands Arrow batches to a Python object.
#![expect(
    clippy::too_many_arguments,
    reason = "pyo3's generated wrapper for #[pymethods] takes the interpreter, the receiver and \
              the raw argument arrays as parameters; the lint fires at the macro call site"
)]

use std::io;
use std::mem::take;
use std::sync::{Arc, Mutex, PoisonError};

use arrow_array::ffi::{FFI_ArrowSchema, to_ffi};
use arrow_array::{Array as _, RecordBatch, StructArray};
use arrow_schema::{ArrowError, Schema, SchemaRef};
use mboxturbo::{DestinationKind, Exporter, MboxTurboError, Output, Staged};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;
use pyo3::types::{PyCapsule, PyTuple};

use crate::errors::MboxTurboError as PyMboxTurboError;

/// The exception a Python exporter raised, kept until the export has been discarded so the call
/// site can raise the original object instead of a core error.
#[derive(Debug, Default)]
pub(crate) struct Failure {
    /// The first exception recorded.
    raised: Mutex<Option<PyErr>>,
}

impl Failure {
    /// Keeps `error` unless an earlier exception is already recorded.
    fn record(&self, error: PyErr) {
        let mut slot = self.raised.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(error);
        }
    }

    /// The recorded exception, if the exporter raised one.
    pub(crate) fn take(&self) -> Option<PyErr> {
        self.raised
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }
}

/// The schema of an export, readable through the Arrow `PyCapsule` interface.
#[pyclass(frozen, module = "mboxturbo", name = "ArrowSchema")]
struct ArrowSchema {
    /// The schema of every batch of the export.
    schema: SchemaRef,
}

#[pymethods]
impl ArrowSchema {
    /// Arrow C schema capsule of the export's schema.
    fn __arrow_c_schema__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyCapsule>> {
        schema_capsule(py, &self.schema)
    }
}

/// One batch of an export, readable through the Arrow `PyCapsule` interface.
#[pyclass(frozen, module = "mboxturbo", name = "ArrowBatch")]
struct ArrowBatch {
    /// The rows of the batch.
    batch: RecordBatch,
}

#[pymethods]
impl ArrowBatch {
    /// Arrow C array capsules of the batch as a struct array, with its schema;
    /// ``requested_schema`` is accepted and ignored.
    #[pyo3(signature = (requested_schema = None))]
    fn __arrow_c_array__<'py>(
        &self,
        py: Python<'py>,
        requested_schema: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyTuple>> {
        drop(requested_schema);
        let data = StructArray::from(self.batch.clone()).into_data();
        let (array, schema) = to_ffi(&data).map_err(|error| arrow_error(&error))?;
        let schema_capsule = PyCapsule::new_with_value(py, schema, c"arrow_schema")?;
        let array_capsule = PyCapsule::new_with_value(py, array, c"arrow_array")?;
        PyTuple::new(py, [schema_capsule.into_any(), array_capsule.into_any()])
    }
}

/// The write target a file exporter receives; its bytes join the staged file when the Python
/// call that wrote them returns.
#[pyclass(frozen, module = "mboxturbo", name = "ExportWriter")]
#[derive(Debug, Default)]
struct ExportWriter {
    /// Bytes written during the current Python call.
    pending: Mutex<Vec<u8>>,
}

#[pymethods]
impl ExportWriter {
    /// Appends ``data`` to the export file and returns its length.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "pyo3 extracts the argument by value; a bytes view is not extractable by reference"
    )]
    fn write(&self, data: PyBackedBytes) -> usize {
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(&data);
        data.len()
    }
}

/// An [`Exporter`] that calls ``begin(schema, out)``, ``write_batch(batch, out)`` and
/// ``finish(out)`` on a Python object. A raised exception is recorded in the shared
/// [`Failure`] and a core error is returned, so the driver discards the staged output.
pub(crate) struct PythonExporter {
    /// Bytes written by ``begin``, counted with the first batch, or at ``finish`` when no batch
    /// was written, because ``begin`` reports none.
    carried: u64,
    /// Where the Python exception goes when a call raises.
    failure: Arc<Failure>,
    /// Whether the exporter writes a file or a directory.
    kind: DestinationKind,
    /// The user's exporter.
    object: Py<PyAny>,
}

/// The `out` argument for a call, with the writer behind it when the destination is a file.
type Out<'py> = (Bound<'py, PyAny>, Option<Bound<'py, ExportWriter>>);

impl PythonExporter {
    /// Calls `method` with the arguments `first` (when given) and the output, then moves what
    /// the call wrote into the staged file; returns how many bytes that was.
    fn call(
        &self,
        staged: &mut Staged,
        method: &str,
        first: Option<PyResult<Py<PyAny>>>,
    ) -> Result<u64, Box<MboxTurboError>> {
        let outcome = Python::attach(|py| {
            let (out, writer) = output(py, staged)?;
            let mut arguments = vec![out];
            if let Some(subject) = first {
                arguments.insert(0, subject?.into_bound(py));
            }
            drop(
                self.object
                    .bind(py)
                    .call_method1(method, PyTuple::new(py, arguments)?)?,
            );
            Ok(writer.map(|bound| drain(bound.get())))
        });
        match outcome {
            Ok(Some(bytes)) => append(staged, &bytes),
            Ok(None) => Ok(0),
            Err(error) => {
                self.failure.record(error);
                Err(Box::new(MboxTurboError::Io {
                    path: staged.target_label().to_path_buf(),
                    source: io::Error::other("the Python exporter raised"),
                }))
            },
        }
    }

    /// The destination kind ``object`` declares with its ``kind`` attribute, ``file`` when it has
    /// none; `ValueError` for any other value.
    pub(crate) fn declared_kind(object: &Bound<'_, PyAny>) -> PyResult<DestinationKind> {
        let Some(declared) = object.getattr_opt("kind")? else {
            return Ok(DestinationKind::File);
        };
        match declared.extract::<&str>()? {
            "file" => Ok(DestinationKind::File),
            "directory" => Ok(DestinationKind::Directory),
            other => Err(PyValueError::new_err(format!(
                "unknown exporter kind '{other}'; expected 'file' or 'directory'"
            ))),
        }
    }

    /// An exporter of `kind` over `object` that records its exceptions in `failure`.
    pub(crate) const fn new(
        object: Py<PyAny>,
        kind: DestinationKind,
        failure: Arc<Failure>,
    ) -> Self {
        Self {
            carried: 0,
            failure,
            kind,
            object,
        }
    }
}

impl Exporter for PythonExporter {
    fn accepts(&self, kind: DestinationKind) -> bool {
        kind == self.kind
    }

    fn begin(&mut self, schema: &SchemaRef, staged: &mut Staged) -> Result<(), MboxTurboError> {
        let subject = Python::attach(|py| {
            let wrapped = ArrowSchema {
                schema: Arc::clone(schema),
            };
            Py::new(py, wrapped).map(Py::into_any)
        });
        self.carried = self
            .call(staged, "begin", Some(subject))
            .map_err(|boxed| *boxed)?;
        Ok(())
    }

    fn finish(&mut self, staged: &mut Staged) -> Result<u64, MboxTurboError> {
        let written = self.call(staged, "finish", None).map_err(|boxed| *boxed)?;
        Ok(written.saturating_add(take(&mut self.carried)))
    }

    fn write(&mut self, batch: &RecordBatch, staged: &mut Staged) -> Result<u64, MboxTurboError> {
        let subject = Python::attach(|py| {
            let wrapped = ArrowBatch {
                batch: batch.clone(),
            };
            Py::new(py, wrapped).map(Py::into_any)
        });
        let written = self
            .call(staged, "write_batch", Some(subject))
            .map_err(|boxed| *boxed)?;
        Ok(written.saturating_add(take(&mut self.carried)))
    }
}

/// The base mboxturbo exception for an Arrow failure.
fn arrow_error(error: &ArrowError) -> PyErr {
    PyMboxTurboError::new_err(error.to_string())
}

/// Appends `bytes` to the staged file and returns their count; a directory takes none.
#[expect(
    clippy::disallowed_methods,
    reason = "usize is at most 64 bits on every supported target, so the conversion never fails"
)]
fn append(staged: &mut Staged, bytes: &[u8]) -> Result<u64, Box<MboxTurboError>> {
    let path = staged.target_label().to_path_buf();
    match staged.output() {
        Output::Writer(writer) => writer
            .write_all(bytes)
            .map_err(|source| Box::new(MboxTurboError::Io { path, source }))?,
        Output::Directory(_) => return Ok(0),
    }
    Ok(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
}

/// The bytes `writer` received since the last call, leaving it empty.
fn drain(writer: &ExportWriter) -> Vec<u8> {
    take(
        &mut *writer
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner),
    )
}

/// The `out` argument for the staged destination, with the writer behind it for a file.
fn output<'py>(py: Python<'py>, staged: &mut Staged) -> PyResult<Out<'py>> {
    match staged.output() {
        Output::Directory(path) => {
            let made = py.import("pathlib")?.getattr("Path")?.call1((path,))?;
            Ok((made, None))
        },
        Output::Writer(_) => {
            let writer = Bound::new(py, ExportWriter::default())?;
            Ok((writer.clone().into_any(), Some(writer)))
        },
    }
}

/// An Arrow C schema capsule for `schema`.
fn schema_capsule<'py>(py: Python<'py>, schema: &Schema) -> PyResult<Bound<'py, PyCapsule>> {
    let exported = FFI_ArrowSchema::try_from(schema).map_err(|error| arrow_error(&error))?;
    PyCapsule::new_with_value(py, exported, c"arrow_schema")
}
