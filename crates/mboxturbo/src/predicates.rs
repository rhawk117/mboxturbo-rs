//! A typed predicate tree over raw header values and authentication verdicts, with a stable
//! JSON form.

use mboxturbo_headers::AuthMethod;
use serde::{Deserialize, Serialize};

use crate::error::{MboxTurboError, PredicateFault};
use crate::filter::Compiled;

/// The authentication method a [`Predicate::Verdict`] reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum VerdictMethod {
    /// The `compauth` result of Microsoft's composite authentication.
    Compauth,
    /// The `dkim` result.
    Dkim,
    /// The `dmarc` result.
    Dmarc,
    /// The `spf` result.
    Spf,
}

/// A condition on the headers of one message.
///
/// Header names match ASCII case-insensitively. A header predicate holds when any value of the
/// header satisfies it, each value taken unfolded onto one line and compared byte for byte, so
/// letter case in the value matters. A header the message lacks never satisfies `Equals`,
/// `Contains`, `StartsWith` or `Regex`, and `Not` of those holds for it.
///
/// A [`Verdict`](Self::Verdict) holds when the topmost trusted `Authentication-Results` header
/// has a result for the method that reads `equals` (`pass`, `fail`, `softfail`, `none` and so
/// on). Trust is decided as for the `verdict_*` columns; a filter given no trust set never
/// satisfies it.
///
/// # JSON
///
/// The JSON form is internally tagged by `op`, written without whitespace, fields in the order
/// shown. [`Predicate::from_json`] and [`Predicate::to_json`] read and write it:
///
/// ```json
/// {"op":"exists","header":"list-id"}
/// {"op":"equals","header":"x-spam-flag","value":"YES"}
/// {"op":"contains","header":"subject","value":"invoice"}
/// {"op":"starts_with","header":"from","value":"billing@"}
/// {"op":"regex","header":"subject","pattern":"^Re: .*[0-9]{4}$"}
/// {"op":"verdict","method":"dmarc","equals":"pass"}
/// {"op":"and","args":[{"op":"exists","header":"list-id"},{"op":"exists","header":"x"}]}
/// {"op":"or","args":[{"op":"exists","header":"a"},{"op":"exists","header":"b"}]}
/// {"op":"not","arg":{"op":"exists","header":"list-id"}}
/// ```
///
/// `method` is one of `dmarc`, `spf`, `dkim` and `compauth`. `and` and `or` take at least one
/// argument. Deserializing with serde alone does not validate; [`Predicate::from_json`],
/// [`Predicate::validate`] and [`Filter::new`](crate::Filter::new) do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Predicate {
    /// Every argument holds.
    And {
        /// The conditions, at least one.
        args: Vec<Self>,
    },
    /// The header holds a value containing `value`.
    Contains {
        /// The header name.
        header: String,
        /// The text a value must contain.
        value: String,
    },
    /// The header holds a value equal to `value`.
    Equals {
        /// The header name.
        header: String,
        /// The text a value must equal.
        value: String,
    },
    /// The message has the header, whatever its value.
    Exists {
        /// The header name.
        header: String,
    },
    /// The argument does not hold.
    Not {
        /// The condition to negate.
        arg: Box<Self>,
    },
    /// At least one argument holds.
    Or {
        /// The conditions, at least one.
        args: Vec<Self>,
    },
    /// The header holds a value the pattern matches anywhere in.
    Regex {
        /// The header name.
        header: String,
        /// A pattern in the `regex` crate's syntax, which matches in linear time.
        pattern: String,
    },
    /// The header holds a value starting with `value`.
    StartsWith {
        /// The header name.
        header: String,
        /// The text a value must start with.
        value: String,
    },
    /// The trusted authentication result of `method` reads `equals`.
    Verdict {
        /// The authentication method.
        method: VerdictMethod,
        /// The result word, such as `pass`.
        equals: String,
    },
}

impl VerdictMethod {
    /// The header-parser method this verdict reads.
    pub(crate) const fn auth_method(self) -> AuthMethod<'static> {
        match self {
            Self::Compauth => AuthMethod::CompAuth,
            Self::Dkim => AuthMethod::Dkim,
            Self::Dmarc => AuthMethod::Dmarc,
            Self::Spf => AuthMethod::Spf,
        }
    }
}

impl Predicate {
    /// `And` of `args`.
    ///
    /// # Errors
    ///
    /// [`MboxTurboError::InvalidPredicate`] when `args` is empty or any argument is invalid.
    pub fn and(args: Vec<Self>) -> Result<Self, MboxTurboError> {
        Self::checked(Self::And { args })
    }

    /// `predicate` when it validates.
    fn checked(predicate: Self) -> Result<Self, MboxTurboError> {
        predicate.validate()?;
        Ok(predicate)
    }

    /// Parses the JSON form described on [`Predicate`] and validates the tree.
    ///
    /// # Errors
    ///
    /// [`MboxTurboError::InvalidPredicate`] at path `json` when `json` is not a predicate, and
    /// otherwise at the path of the first empty `and` or `or` or pattern that does not compile.
    pub fn from_json(json: &str) -> Result<Self, MboxTurboError> {
        let predicate: Self =
            serde_json::from_str(json).map_err(|source| MboxTurboError::InvalidPredicate {
                path: "json".to_owned(),
                fault: Box::new(PredicateFault::Json(source)),
            })?;
        predicate.validate()?;
        Ok(predicate)
    }

    /// `Or` of `args`.
    ///
    /// # Errors
    ///
    /// [`MboxTurboError::InvalidPredicate`] when `args` is empty or any argument is invalid.
    pub fn or(args: Vec<Self>) -> Result<Self, MboxTurboError> {
        Self::checked(Self::Or { args })
    }

    /// `Regex` of `pattern` over the values of `header`.
    ///
    /// # Errors
    ///
    /// [`MboxTurboError::InvalidPredicate`] at path `regex`, naming the pattern, when it does
    /// not compile within the size limit.
    pub fn regex(header: &str, pattern: &str) -> Result<Self, MboxTurboError> {
        Self::checked(Self::Regex {
            header: header.to_owned(),
            pattern: pattern.to_owned(),
        })
    }

    /// The compact JSON form described on [`Predicate`].
    ///
    /// # Errors
    ///
    /// The serializer's error, which a predicate cannot cause.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Checks that no `and` or `or` is empty and every pattern compiles.
    ///
    /// # Errors
    ///
    /// [`MboxTurboError::InvalidPredicate`] for the first fault in a depth-first walk, with its
    /// path (for example `and[1].regex`) and, for a pattern, the pattern.
    pub fn validate(&self) -> Result<(), MboxTurboError> {
        Compiled::build(self, "").map(drop)
    }
}
