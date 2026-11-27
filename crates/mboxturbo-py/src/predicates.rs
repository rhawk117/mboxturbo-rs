//! Predicate and trust-set builders: ordinary Python expressions that convert to the core types.
#![expect(
    clippy::too_many_arguments,
    reason = "pyo3's generated wrapper for #[pymethods] takes the interpreter, the receiver and \
              the raw argument arrays as parameters; the lint fires at the macro call site, so an \
              expectation on the impl block is unfulfilled and it must stay at module scope; no \
              signature in this module has that many"
)]
#![expect(
    clippy::multiple_inherent_impl,
    reason = "#[pymethods] must sit alone in its impl block, and the crate-internal accessors \
              and helpers cannot join it"
)]

use std::error::Error;

use mboxturbo::VerdictMethod;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::errors::MboxTurboError;

/// The method words `verdict` accepts, in the order its error message lists them.
const METHODS: &str = "dmarc, spf, dkim, compauth";

/// Which combination `&` or `|` builds.
#[derive(Debug, Clone, Copy)]
enum Operator {
    /// Every operand holds.
    And,
    /// At least one operand holds.
    Or,
}

/// A condition on message headers or authentication verdicts. Build one with ``header(...)`` or
/// ``verdict(...)`` and combine with ``&``, ``|`` and ``~``. Invalid predicates fail when built.
#[pyclass(frozen, eq, module = "mboxturbo")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Predicate {
    /// The validated core predicate this wraps.
    inner: mboxturbo::Predicate,
}

impl Predicate {
    /// `And` or `Or` of both sides, flattened, or `NotImplemented` when `rhs` is no predicate.
    fn combine(
        &self,
        py: Python<'_>,
        rhs: &Bound<'_, PyAny>,
        operator: Operator,
    ) -> PyResult<Py<PyAny>> {
        let Ok(right) = rhs.cast::<Self>() else {
            return Ok(py.NotImplemented());
        };
        let mut args = self.operands(operator);
        args.extend(right.get().operands(operator));
        let combined = match operator {
            Operator::And => mboxturbo::Predicate::and(args),
            Operator::Or => mboxturbo::Predicate::or(args),
        };
        let inner = combined.map_err(|error| invalid(&error))?;
        Ok(Self { inner }.into_pyobject(py)?.into_any().unbind())
    }

    /// The JSON form of the wrapped predicate.
    fn json(&self) -> PyResult<String> {
        self.inner
            .to_json()
            .map_err(|error| PyValueError::new_err(error.to_string()))
    }

    /// The arguments this predicate contributes to a combination: its own when it is the same
    /// operator, itself otherwise, so nested combinations flatten.
    fn operands(&self, operator: Operator) -> Vec<mboxturbo::Predicate> {
        match (&self.inner, operator) {
            (mboxturbo::Predicate::And { args }, Operator::And)
            | (mboxturbo::Predicate::Or { args }, Operator::Or) => args.clone(),
            (single, Operator::And | Operator::Or) => vec![single.clone()],
        }
    }

    /// The core predicate, for the selection that filters with it.
    #[expect(
        dead_code,
        reason = "select(where=) takes the core predicate in the next task"
    )]
    pub(crate) const fn predicate(&self) -> &mboxturbo::Predicate {
        &self.inner
    }
}

#[pymethods]
impl Predicate {
    /// ``self & other``: both hold.
    fn __and__(&self, py: Python<'_>, other: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        self.combine(py, other, Operator::And)
    }

    /// ``~self``: the predicate does not hold.
    fn __invert__(&self) -> Self {
        Self {
            inner: mboxturbo::Predicate::Not {
                arg: Box::new(self.inner.clone()),
            },
        }
    }

    /// ``self | other``: at least one holds.
    fn __or__(&self, py: Python<'_>, other: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        self.combine(py, other, Operator::Or)
    }

    /// ``Predicate(<json>)``.
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("Predicate({})", self.json()?))
    }

    /// Parses the JSON form and validates it; a malformed, empty or uncompilable predicate
    /// raises ``MboxTurboError``.
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        let inner = mboxturbo::Predicate::from_json(json).map_err(|error| invalid(&error))?;
        Ok(Self { inner })
    }

    /// The compact JSON form, which ``from_json`` reads back.
    fn to_json(&self) -> PyResult<String> {
        self.json()
    }
}

/// Builds predicates over the values of one header, matched ASCII case-insensitively by name.
#[pyclass(frozen, module = "mboxturbo")]
#[derive(Debug, Clone)]
pub(crate) struct HeaderBuilder {
    /// The header name.
    name: String,
}

#[pymethods]
impl HeaderBuilder {
    /// A value contains ``value``.
    fn contains(&self, value: &Bound<'_, PyAny>) -> PyResult<Predicate> {
        Ok(Predicate {
            inner: mboxturbo::Predicate::Contains {
                header: self.name.clone(),
                value: text(value)?,
            },
        })
    }

    /// A value equals ``value`` byte for byte.
    fn equals(&self, value: &Bound<'_, PyAny>) -> PyResult<Predicate> {
        Ok(Predicate {
            inner: mboxturbo::Predicate::Equals {
                header: self.name.clone(),
                value: text(value)?,
            },
        })
    }

    /// The message has the header, whatever its value.
    fn exists(&self) -> Predicate {
        Predicate {
            inner: mboxturbo::Predicate::Exists {
                header: self.name.clone(),
            },
        }
    }

    /// A value matches the regular expression ``pattern`` anywhere; one that does not compile
    /// raises ``MboxTurboError`` here.
    fn matches(&self, pattern: &Bound<'_, PyAny>) -> PyResult<Predicate> {
        let inner = mboxturbo::Predicate::regex(&self.name, &text(pattern)?)
            .map_err(|error| invalid(&error))?;
        Ok(Predicate { inner })
    }

    /// A value starts with ``value``.
    fn startswith(&self, value: &Bound<'_, PyAny>) -> PyResult<Predicate> {
        Ok(Predicate {
            inner: mboxturbo::Predicate::StartsWith {
                header: self.name.clone(),
                value: text(value)?,
            },
        })
    }
}

/// Builds predicates over the trusted authentication result of one method.
#[pyclass(frozen, module = "mboxturbo")]
#[derive(Debug, Clone)]
pub(crate) struct VerdictBuilder {
    /// The authentication method read.
    method: VerdictMethod,
}

#[pymethods]
impl VerdictBuilder {
    /// The trusted result reads ``result`` (``pass``, ``fail``, ``softfail``, ``none`` ...).
    fn equals(&self, result: &Bound<'_, PyAny>) -> PyResult<Predicate> {
        Ok(Predicate {
            inner: mboxturbo::Predicate::Verdict {
                method: self.method,
                equals: text(result)?,
            },
        })
    }
}

/// The trusted hosts, IP ranges and authserv-ids whose ``Authentication-Results`` count for
/// ``verdict`` predicates. An empty set trusts nothing.
#[pyclass(frozen, module = "mboxturbo")]
#[derive(Debug, Clone)]
pub(crate) struct Trust {
    /// The built trust set.
    inner: mboxturbo::TrustSet,
}

impl Trust {
    /// The core trust set, for the selection that filters with it.
    #[expect(
        dead_code,
        reason = "select(trust=) takes the core trust set in the next task"
    )]
    pub(crate) const fn trust_set(&self) -> &mboxturbo::TrustSet {
        &self.inner
    }
}

#[pymethods]
impl Trust {
    /// Trusts the given hosts (and their subdomains), IP addresses or CIDR ranges and
    /// authserv-ids; a malformed range raises ``ValueError`` naming it and the byte offset.
    #[new]
    #[pyo3(signature = (
        *,
        hosts = Vec::new(),
        ip_ranges = Vec::new(),
        authserv_ids = Vec::new(),
        trust_idless_inside = false
    ))]
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "Python's `trust_idless_inside=` keyword is a bool by the requested interface"
    )]
    fn new(
        hosts: Vec<String>,
        ip_ranges: Vec<String>,
        authserv_ids: Vec<String>,
        trust_idless_inside: bool,
    ) -> PyResult<Self> {
        let mut inner = mboxturbo::TrustSet::new();
        for host in hosts {
            let _chain = inner.add_host(&host);
        }
        for range in ip_ranges {
            let _chain = inner.add_ip_range(&range).map_err(|fault| {
                PyValueError::new_err(format!(
                    "invalid IP range {range:?} at byte {}",
                    fault.offset()
                ))
            })?;
        }
        for id in authserv_ids {
            let _chain = inner.add_authserv_id(&id);
        }
        let _chain = inner.trust_idless_inside(trust_idless_inside);
        Ok(Self { inner })
    }
}

/// A header predicate builder for ``name``; an empty name raises ``ValueError``.
#[pyfunction]
pub(crate) fn header(name: &str) -> PyResult<HeaderBuilder> {
    if name.is_empty() {
        return Err(PyValueError::new_err("header name must not be empty"));
    }
    Ok(HeaderBuilder {
        name: name.to_owned(),
    })
}

/// A verdict predicate builder for ``method``, one of dmarc, spf, dkim and compauth.
#[pyfunction]
pub(crate) fn verdict(method: &str) -> PyResult<VerdictBuilder> {
    let parsed = match method {
        "dmarc" => VerdictMethod::Dmarc,
        "spf" => VerdictMethod::Spf,
        "dkim" => VerdictMethod::Dkim,
        "compauth" => VerdictMethod::Compauth,
        unknown => {
            return Err(PyValueError::new_err(format!(
                "verdict method must be one of {METHODS}, got {unknown:?}"
            )));
        },
    };
    Ok(VerdictBuilder { method: parsed })
}

/// The text of a ``str`` or UTF-8 ``bytes`` argument.
fn text(value: &Bound<'_, PyAny>) -> PyResult<String> {
    if let Ok(bytes) = value.cast::<PyBytes>() {
        return str::from_utf8(bytes.as_bytes())
            .map(str::to_owned)
            .map_err(|error| PyValueError::new_err(format!("bytes are not UTF-8: {error}")));
    }
    value.extract()
}

/// The base exception for a rejected predicate, its message the error and every cause, so the
/// pattern that failed to compile is named.
fn invalid(error: &mboxturbo::MboxTurboError) -> PyErr {
    let mut message = error.to_string();
    let mut cause = Error::source(error);
    while let Some(next) = cause {
        message.push_str(": ");
        message.push_str(&next.to_string());
        cause = next.source();
    }
    MboxTurboError::new_err(message)
}
