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

pub(crate) fn into_py_err(py: Python<'_>, error: mboxturbo::Error) -> PyErr {
    let message = error.to_string();
    match error {
        mboxturbo::Error::Io { path, source } => {
            let raised = PyErr::from(source);
            let tagged = raised.value(py).setattr(intern!(py, "filename"), path);
            tagged.err().unwrap_or(raised)
        },
        mboxturbo::Error::CorruptIndex { .. } => CorruptIndexError::new_err(message),
        mboxturbo::Error::StaleIndex { .. } => StaleIndexError::new_err(message),
        mboxturbo::Error::Arrow { .. } | mboxturbo::Error::Parquet { .. } => {
            MboxTurboError::new_err(message)
        },
    }
}

pub(crate) fn closed() -> PyErr {
    PyValueError::new_err("I/O operation on a closed mailbox")
}
