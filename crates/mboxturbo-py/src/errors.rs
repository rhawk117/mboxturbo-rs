//! The Python exception hierarchy and the mapping from core errors onto it.

use pyo3::exceptions::{PyException, PyValueError};
use pyo3::prelude::*;
use pyo3::{create_exception, intern};

create_exception!(
    mboxturbo,
    MboxTurboError,
    PyException,
    "Base class for mboxturbo errors."
);
create_exception!(
    mboxturbo,
    CorruptIndexError,
    MboxTurboError,
    "An index file exists but is damaged or is not an mboxturbo index."
);
create_exception!(
    mboxturbo,
    StaleIndexError,
    MboxTurboError,
    "An index file was built for a different version of the mailbox."
);

/// The Python exception for a core error: `OSError` (with `filename`) for I/O, the matching
/// `MboxTurboError` subclass for a damaged or stale index, the base class otherwise.
pub(crate) fn into_py_err(py: Python<'_>, error: mboxturbo::MboxTurboError) -> PyErr {
    let message = error.to_string();
    match error {
        mboxturbo::MboxTurboError::Io { path, source } => {
            let raised = PyErr::from(source);
            let tagged = raised.value(py).setattr(intern!(py, "filename"), path);
            tagged.err().unwrap_or(raised)
        },
        mboxturbo::MboxTurboError::CorruptIndex { .. } => CorruptIndexError::new_err(message),
        mboxturbo::MboxTurboError::StaleIndex { .. } => StaleIndexError::new_err(message),
        mboxturbo::MboxTurboError::Arrow { .. } | mboxturbo::MboxTurboError::Parquet { .. } => {
            MboxTurboError::new_err(message)
        },
        _ => MboxTurboError::new_err(message),
    }
}

/// The `ValueError` raised when a closed mailbox is used.
pub(crate) fn closed() -> PyErr {
    PyValueError::new_err("I/O operation on a closed mailbox")
}
