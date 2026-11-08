//! Column selections: streamed through the Arrow C stream interface or written to Parquet.
#![expect(
    clippy::too_many_arguments,
    reason = "pyo3's generated wrapper for #[pymethods] takes the interpreter, the receiver and \
              the raw argument arrays as parameters; no signature in this module has that many"
)]

use std::path::PathBuf;
use std::sync::Arc;

use arrow_array::ffi_stream::FFI_ArrowArrayStream;
use mboxturbo::{Column, Compression, Pipeline};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyCapsule;

use crate::errors::into_py_err;

/// Chosen columns over a mailbox. Any Arrow consumer reads it directly (``pyarrow.table``,
/// ``polars.DataFrame``, ``DuckDB``), and ``to_parquet`` writes it to a file. Each read extracts
/// afresh, in parallel, parsing only what the columns need.
#[pyclass(frozen, module = "mboxturbo")]
#[derive(Debug)]
pub(crate) struct Selection {
    /// The mapping the columns are extracted from.
    mailbox: Arc<mboxturbo::Mailbox>,
    /// The column names, in selection order.
    names: Vec<String>,
    /// The extraction plan shared by every read.
    pipeline: Arc<Pipeline>,
}

#[pymethods]
impl Selection {
    #[pyo3(signature = (requested_schema = None))]
    /// Arrow C stream capsule over the selection; ``requested_schema`` is accepted and ignored.
    fn __arrow_c_stream__<'py>(
        &self,
        py: Python<'py>,
        requested_schema: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyCapsule>> {
        drop(requested_schema);
        let reader = self.pipeline.reader(&self.mailbox);
        let stream = FFI_ArrowArrayStream::new(Box::new(reader));
        PyCapsule::new_with_value(py, stream, c"arrow_array_stream")
    }

    /// ``Selection(columns=N, messages=M)``.
    fn __repr__(&self) -> String {
        format!(
            "Selection(columns={}, messages={})",
            self.names.len(),
            self.mailbox.len()
        )
    }

    /// Names of the selected columns, in order.
    #[getter]
    fn columns(&self) -> Vec<String> {
        self.names.clone()
    }

    /// Writes the selection to a Parquet file at ``path`` atomically and returns the row count.
    #[pyo3(signature = (path, *, compression = "zstd"))]
    fn to_parquet(&self, py: Python<'_>, path: PathBuf, compression: &str) -> PyResult<u64> {
        let codec = parse_compression(compression)?;
        let mailbox = Arc::clone(&self.mailbox);
        let pipeline = Arc::clone(&self.pipeline);
        py.detach(move || {
            pipeline
                .write_parquet(&mailbox, &path, codec)
                .map_err(Box::new)
        })
        .map_err(|error| into_py_err(py, *error))
    }
}

/// A selection over `mailbox`; `ValueError` for a zero `batch_size` or an unknown column, with
/// every column in `Column::defaults` when `requested` is `None`.
pub(crate) fn select_columns(
    mailbox: Arc<mboxturbo::Mailbox>,
    requested: Option<Vec<String>>,
    batch_size: usize,
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
    let pipeline = Arc::new(Pipeline::new(columns, batch_size));
    Ok(Selection {
        mailbox,
        names,
        pipeline,
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
