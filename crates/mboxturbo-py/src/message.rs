//! `Message`, `Address` and `Attachment`: Python views over a lazily parsed core message.
#![expect(
    clippy::too_many_arguments,
    reason = "pyo3's generated wrapper for #[pymethods] takes the interpreter, the receiver and \
              the raw argument arrays as parameters; the lint fires at the macro call site, so an \
              expectation on the impl block is unfulfilled and it must stay at module scope; no \
              signature in this module has that many"
)]

use std::borrow::Cow;
use std::hash::{DefaultHasher, Hash as _, Hasher as _};

use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDateTime, PyDelta, PyDict, PyString, PyTzInfo};

/// One message from a mailbox. Fields parse in Rust on first access and are not copied out
/// of the mapping until read.
#[pyclass(frozen, module = "mboxturbo")]
#[derive(Debug)]
pub(crate) struct Message {
    /// The core message every property reads from.
    inner: mboxturbo::Message,
}

impl From<mboxturbo::Message> for Message {
    /// Wraps a core message without copying it.
    fn from(inner: mboxturbo::Message) -> Self {
        Self { inner }
    }
}

/// A mailbox address from a header; either part may be missing.
#[pyclass(frozen, get_all, eq, module = "mboxturbo")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Address {
    /// The ``local@domain`` part, when the header has one.
    email: Option<String>,
    /// The display name, when the header has one.
    name: Option<String>,
}

/// A decoded attachment.
#[pyclass(frozen, get_all, module = "mboxturbo")]
#[derive(Debug)]
pub(crate) struct Attachment {
    /// The media type, when it declares one.
    content_type: Option<String>,
    /// The decoded content.
    data: Py<PyBytes>,
    /// The attachment's file name, when it declares one.
    filename: Option<String>,
}

#[pymethods]
impl Address {
    /// Hash consistent with equality: equal addresses hash equal.
    fn __hash__(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }

    /// ``Address(name=..., email=...)`` with each part as a Python ``repr``.
    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        Ok(format!(
            "Address(name={}, email={})",
            python_repr(py, self.name.as_deref())?,
            python_repr(py, self.email.as_deref())?
        ))
    }
}

#[pymethods]
impl Attachment {
    /// ``Attachment(filename=..., content_type=..., size=N)`` with ``size`` in bytes.
    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        Ok(format!(
            "Attachment(filename={}, content_type={}, size={})",
            python_repr(py, self.filename.as_deref())?,
            python_repr(py, self.content_type.as_deref())?,
            self.data.bind(py).as_bytes().len()
        ))
    }
}

#[pymethods]
impl Message {
    /// ``Message(subject=..., size=N)`` with ``size`` the raw length in bytes.
    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        Ok(format!(
            "Message(subject={}, size={})",
            python_repr(py, self.inner.subject())?,
            self.inner.raw().len()
        ))
    }

    /// Every attachment, decoded.
    #[getter]
    fn attachments(&self, py: Python<'_>) -> Vec<Attachment> {
        self.inner
            .attachments()
            .map(|attachment| Attachment {
                filename: attachment.filename.map(str::to_owned),
                content_type: attachment.content_type(),
                data: PyBytes::new(py, &attachment.data).unbind(),
            })
            .collect()
    }

    /// Every address in ``Cc:``.
    #[getter]
    fn cc(&self) -> Vec<Address> {
        self.inner.cc().map(Address::from).collect()
    }

    /// ``Date:`` as an aware datetime in the header's own UTC offset.
    #[getter]
    fn date<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyDateTime>>> {
        self.inner
            .date()
            .map(|timestamp| aware_datetime(py, timestamp))
            .transpose()
    }

    /// Every address in ``From:``.
    #[getter]
    fn from_(&self) -> Vec<Address> {
        self.inner.from().map(Address::from).collect()
    }

    /// First value of the header called ``name`` (any case), unfolded; encoded words are
    /// left as written.
    fn get(&self, name: &str) -> Option<Cow<'_, str>> {
        self.inner.header(name)
    }

    /// Every value of the header called ``name`` (any case) in file order, unfolded.
    fn get_all(&self, name: &str) -> Vec<Cow<'_, str>> {
        self.inner.header_values(name).collect()
    }

    /// HTML bodies; a text-only message yields its text converted to HTML.
    #[getter]
    fn html(&self) -> Vec<Cow<'_, str>> {
        self.inner.html_bodies().collect()
    }

    /// ``Message-ID:`` without angle brackets.
    #[getter]
    fn message_id(&self) -> Option<&str> {
        self.inner.message_id()
    }

    /// Raw bytes exactly as stored, including the mbox ``From `` separator line.
    #[getter]
    fn raw<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.raw())
    }

    /// Decoded ``Subject:``.
    #[getter]
    fn subject(&self) -> Option<&str> {
        self.inner.subject()
    }

    /// Plain-text bodies; an HTML-only message yields its HTML converted to text.
    #[getter]
    fn text(&self) -> Vec<Cow<'_, str>> {
        self.inner.text_bodies().collect()
    }

    /// Every address in ``To:``.
    #[getter]
    fn to(&self) -> Vec<Address> {
        self.inner.to().map(Address::from).collect()
    }

    /// The same message parsed by the standard library, for code that needs ``EmailMessage``.
    fn to_email_message<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let policy = py
            .import(intern!(py, "email.policy"))?
            .getattr(intern!(py, "default"))?;
        let options = PyDict::new(py);
        options.set_item(intern!(py, "policy"), policy)?;
        py.import(intern!(py, "email"))?
            .getattr(intern!(py, "message_from_bytes"))?
            .call((self.raw(py),), Some(&options))
    }
}

impl From<mboxturbo::Address<'_>> for Address {
    /// Copies the borrowed parts so the address outlives the message.
    fn from(address: mboxturbo::Address<'_>) -> Self {
        Self {
            name: address.name.map(str::to_owned),
            email: address.email.map(str::to_owned),
        }
    }
}

/// Python's ``repr`` of the text, or ``None`` for a missing value.
fn python_repr(py: Python<'_>, value: Option<&str>) -> PyResult<String> {
    value.map_or_else(
        || Ok("None".to_owned()),
        |text| Ok(PyString::new(py, text).repr()?.to_string()),
    )
}

/// The timestamp as a datetime aware of the header's own UTC offset.
#[expect(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    clippy::disallowed_methods,
    reason = "unix seconds below 2^53 convert to f64 exactly, which covers every date until \
              the year 285 million; the core parser caps |offset_minutes| below 24 * 60, so \
              * 60 fits in i32"
)]
fn aware_datetime(
    py: Python<'_>,
    timestamp: mboxturbo::Timestamp,
) -> PyResult<Bound<'_, PyDateTime>> {
    let offset = PyDelta::new(py, 0, timestamp.offset_minutes.strict_mul(60), 0, true)?;
    let zone = PyTzInfo::fixed_offset(py, offset)?;
    PyDateTime::from_timestamp(py, timestamp.unix_seconds as f64, Some(&zone))
}
