//! The Python exception hierarchy and the mapping from core errors onto it.

use pyo3::exceptions::{PyException, PyFileExistsError, PyValueError};
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
create_exception!(
    mboxturbo,
    Cancelled,
    MboxTurboError,
    "An export was stopped by a cancel token, Ctrl-C or a raising progress callback."
);

/// The Python exception for a core error: `OSError` (with `filename`) for I/O, the matching
/// `MboxTurboError` subclass for a damaged or stale index, `Cancelled` for a stopped export,
/// `FileExistsError` (with `filename`) for an existing export target (or one that overwriting may
/// not replace), `ValueError` for a column a sink cannot use, the base class otherwise (Arrow,
/// encoder, Parquet, invalid predicate and out-of-range position errors included).
pub(crate) fn into_py_err(py: Python<'_>, error: mboxturbo::MboxTurboError) -> PyErr {
    let message = error.to_string();
    match error {
        mboxturbo::MboxTurboError::Io { path, source } => {
            let raised = PyErr::from(source);
            let tagged = raised.value(py).setattr(intern!(py, "filename"), path);
            tagged.err().unwrap_or(raised)
        },
        mboxturbo::MboxTurboError::TargetExists { path }
        | mboxturbo::MboxTurboError::TargetNotReplaceable { path, .. } => {
            let raised = PyFileExistsError::new_err(message);
            let tagged = raised.value(py).setattr(intern!(py, "filename"), path);
            tagged.err().unwrap_or(raised)
        },
        mboxturbo::MboxTurboError::CorruptIndex { .. } => CorruptIndexError::new_err(message),
        mboxturbo::MboxTurboError::StaleIndex { .. } => StaleIndexError::new_err(message),
        mboxturbo::MboxTurboError::Cancelled { .. } => Cancelled::new_err(message),
        // Naming each variant that raises the base class keeps
        // `clippy::wildcard_enum_match_arm` quiet for the wildcard below.
        mboxturbo::MboxTurboError::UnsupportedColumn { .. } => PyValueError::new_err(message),
        mboxturbo::MboxTurboError::Arrow { .. }
        | mboxturbo::MboxTurboError::Encode { .. }
        | mboxturbo::MboxTurboError::InvalidPredicate { .. }
        | mboxturbo::MboxTurboError::Parquet { .. }
        | mboxturbo::MboxTurboError::PositionOutOfRange { .. }
        | mboxturbo::MboxTurboError::UnsupportedDestination { .. } => {
            MboxTurboError::new_err(message)
        },
        // The Python API is frozen (plan invariant I2): the non-exhaustive remainder raises the
        // base class. A new core variant needs an explicit decision about its Python exception,
        // not this fallback.
        _ => MboxTurboError::new_err(message),
    }
}

/// The `ValueError` raised when a closed mailbox is used.
pub(crate) fn closed() -> PyErr {
    PyValueError::new_err("I/O operation on a closed mailbox")
}
