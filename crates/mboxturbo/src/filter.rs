//! A pass over a mailbox that keeps the messages whose headers satisfy a [`Predicate`].

use std::borrow::Cow;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use mboxturbo_headers::{AuthMethod, TrustSet};
use rayon::prelude::*;
use regex::{Regex, RegexBuilder};

use crate::error::{MboxTurboError, PredicateFault};
use crate::fields::{raw_headers, unfold};
use crate::mailbox::Mailbox;
use crate::predicates::Predicate;
use crate::structured::verdict_is;
use crate::width::widen;

/// The compiled-program size a pattern may reach, in bytes.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// The header whose results a verdict reads.
const AUTHENTICATION_RESULTS: &str = "authentication-results";

/// The header that places an id-less `Authentication-Results` relative to the first external hop.
const RECEIVED: &str = "received";

/// A header name and its raw value, as [`raw_headers`] yields them.
type Header<'bytes> = (&'bytes [u8], &'bytes [u8]);

/// How a text predicate compares a header value with its operand.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Compare {
    /// The value contains the operand.
    Contains,
    /// The value equals the operand.
    Equals,
    /// The value starts with the operand.
    StartsWith,
}

/// A [`Predicate`] with its patterns compiled.
#[derive(Debug)]
pub(crate) enum Compiled {
    /// Every part holds.
    All(Vec<Self>),
    /// At least one part holds.
    Any(Vec<Self>),
    /// The header is present.
    Exists(String),
    /// The part does not hold.
    Negated(Box<Self>),
    /// A value of the header matches the pattern.
    Pattern {
        /// The header name.
        header: String,
        /// The compiled pattern.
        regex: Regex,
    },
    /// A value of the header satisfies the comparison.
    Text {
        /// How the value is compared.
        compare: Compare,
        /// The header name.
        header: String,
        /// The operand.
        value: String,
    },
    /// The trusted result of the method reads the word.
    Verdict {
        /// The authentication method.
        method: AuthMethod<'static>,
        /// The result word.
        word: String,
    },
}

/// Keeps the messages of a mailbox whose headers satisfy a predicate.
///
/// Only the headers the predicate names are read, plus `Authentication-Results` and `Received`
/// when it holds a [`Predicate::Verdict`]; the rest of each message is not parsed.
#[derive(Debug)]
pub struct Filter {
    /// The number of header values handed to the predicate so far, over every pass.
    collected: AtomicU64,
    /// The predicate, compiled.
    compiled: Compiled,
    /// The lowercase names of the headers to read.
    names: Vec<String>,
    /// The trust set deciding verdicts, if any.
    trust: Option<TrustSet>,
}

impl Compiled {
    /// Compiles `predicate`, which sits at `path` in its tree (empty at the root).
    ///
    /// # Errors
    ///
    /// [`MboxTurboError::InvalidPredicate`] for the first empty `and` or `or`, or pattern that
    /// does not compile, with its path.
    pub(crate) fn build(predicate: &Predicate, path: &str) -> Result<Self, MboxTurboError> {
        match predicate {
            Predicate::And { args } => list("and", args, path).map(Self::All),
            Predicate::Contains { header, value } => Ok(text(Compare::Contains, header, value)),
            Predicate::Equals { header, value } => Ok(text(Compare::Equals, header, value)),
            Predicate::Exists { header } => Ok(Self::Exists(header.clone())),
            Predicate::Not { arg } => Self::build(arg, &join(path, "not")).map(Self::negate),
            Predicate::Or { args } => list("or", args, path).map(Self::Any),
            Predicate::Regex { header, pattern } => Ok(Self::Pattern {
                header: header.clone(),
                regex: compile(pattern, &join(path, "regex"))?,
            }),
            Predicate::StartsWith { header, value } => Ok(text(Compare::StartsWith, header, value)),
            Predicate::Verdict { method, equals } => Ok(Self::Verdict {
                method: method.auth_method(),
                word: equals.clone(),
            }),
        }
    }

    /// Whether the headers of one message satisfy this part.
    fn holds(&self, headers: &[Header<'_>], trust: Option<&TrustSet>) -> bool {
        match self {
            Self::All(parts) => parts.iter().all(|part| part.holds(headers, trust)),
            Self::Any(parts) => parts.iter().any(|part| part.holds(headers, trust)),
            Self::Text {
                compare,
                header,
                value,
            } => values(headers, header).any(|text| compare.holds(&text, value)),
            Self::Exists(header) => values(headers, header).next().is_some(),
            Self::Negated(part) => !part.holds(headers, trust),
            Self::Pattern { header, regex } => {
                values(headers, header).any(|text| regex.is_match(&text))
            },
            Self::Verdict { method, word } => {
                trust.is_some() && verdict_is(headers.iter().copied(), method, trust, word)
            },
        }
    }

    /// `part` negated.
    fn negate(part: Self) -> Self {
        Self::Negated(Box::new(part))
    }
}

impl Compare {
    /// Whether `text` relates to `operand` this way.
    fn holds(self, text: &str, operand: &str) -> bool {
        match self {
            Self::Contains => text.contains(operand),
            Self::Equals => text == operand,
            Self::StartsWith => text.starts_with(operand),
        }
    }
}

impl Filter {
    /// The number of header values handed to the predicate across every pass so far.
    ///
    /// A predicate naming only `Subject` collects one value per message that has the header
    /// and none from `Received` or `Authentication-Results`.
    #[must_use]
    pub fn headers_collected(&self) -> u64 {
        self.collected.load(Ordering::Relaxed)
    }

    /// Whether the head of `message` satisfies the predicate.
    fn matches(&self, message: &[u8]) -> bool {
        let headers: Vec<Header<'_>> = raw_headers(message)
            .filter(|&(name, _)| {
                self.names
                    .iter()
                    .any(|wanted| name.eq_ignore_ascii_case(wanted.as_bytes()))
            })
            .collect();
        let _previous = self
            .collected
            .fetch_add(widen(headers.len()), Ordering::Relaxed);
        self.compiled.holds(&headers, self.trust.as_ref())
    }

    /// A filter for `predicate`, with no trust set.
    ///
    /// # Errors
    ///
    /// [`MboxTurboError::InvalidPredicate`] when `predicate` has an empty `and` or `or` or a
    /// pattern that does not compile.
    pub fn new(predicate: &Predicate) -> Result<Self, MboxTurboError> {
        let mut names = Vec::new();
        collect_names(predicate, &mut names);
        Ok(Self {
            collected: AtomicU64::new(0),
            compiled: Compiled::build(predicate, "")?,
            names,
            trust: None,
        })
    }

    /// The positions of the messages of `mailbox` that satisfy the predicate, ascending.
    ///
    /// Messages are examined on all rayon threads. Hand the result to
    /// [`Selection::Positions`](crate::Selection::Positions) after converting to `usize`.
    ///
    /// # Errors
    ///
    /// None today; the signature leaves room for failures of reading the mailbox.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "the signature reserves failures of reading the mailbox; callers already handle \
                  MboxTurboError"
    )]
    pub fn positions(&self, mailbox: &Arc<Mailbox>) -> Result<Vec<u64>, MboxTurboError> {
        Ok(mailbox
            .par_iter()
            .enumerate()
            .filter(|&(_, message)| self.matches(message))
            .map(|(position, _)| widen(position))
            .collect())
    }

    /// This filter deciding verdicts by `trust`.
    #[must_use]
    pub fn with_trust(mut self, trust: TrustSet) -> Self {
        self.trust = Some(trust);
        self
    }
}

/// The compiled parts of an `and` or `or` called `operator` at `path`.
fn list(operator: &str, args: &[Predicate], path: &str) -> Result<Vec<Compiled>, MboxTurboError> {
    let own = join(path, operator);
    if args.is_empty() {
        return Err(MboxTurboError::InvalidPredicate {
            path: own,
            fault: Box::new(PredicateFault::EmptyList),
        });
    }
    args.iter()
        .enumerate()
        .map(|(index, arg)| Compiled::build(arg, &format!("{own}[{index}]")))
        .collect()
}

/// `pattern` compiled under the size limit; `path` locates it in the predicate.
fn compile(pattern: &str, path: &str) -> Result<Regex, MboxTurboError> {
    RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|source| MboxTurboError::InvalidPredicate {
            path: path.to_owned(),
            fault: Box::new(PredicateFault::Regex {
                pattern: pattern.to_owned(),
                source,
            }),
        })
}

/// Adds the lowercase name of every header `predicate` reads to `names`.
fn collect_names(predicate: &Predicate, names: &mut Vec<String>) {
    match predicate {
        Predicate::And { args } | Predicate::Or { args } => {
            for arg in args {
                collect_names(arg, names);
            }
        },
        Predicate::Contains { header, .. }
        | Predicate::Equals { header, .. }
        | Predicate::Exists { header }
        | Predicate::Regex { header, .. }
        | Predicate::StartsWith { header, .. } => add_name(header, names),
        Predicate::Not { arg } => collect_names(arg, names),
        Predicate::Verdict { .. } => {
            add_name(AUTHENTICATION_RESULTS, names);
            add_name(RECEIVED, names);
        },
    }
}

/// Adds `name` in lowercase to `names` unless it is there.
fn add_name(name: &str, names: &mut Vec<String>) {
    let lower = name.to_ascii_lowercase();
    if !names.contains(&lower) {
        names.push(lower);
    }
}

/// `path` with `segment` below it.
fn join(path: &str, segment: &str) -> String {
    if path.is_empty() {
        segment.to_owned()
    } else {
        format!("{path}.{segment}")
    }
}

/// A text part comparing values of `header` with `value`.
fn text(compare: Compare, header: &str, value: &str) -> Compiled {
    Compiled::Text {
        compare,
        header: header.to_owned(),
        value: value.to_owned(),
    }
}

/// The unfolded value of every header called `name` (any case) in `headers`, in file order.
fn values<'bytes>(
    headers: &'bytes [Header<'bytes>],
    name: &'bytes str,
) -> impl Iterator<Item = Cow<'bytes, str>> {
    headers
        .iter()
        .filter(move |(candidate, _)| candidate.eq_ignore_ascii_case(name.as_bytes()))
        .map(|&(_, value)| unfold(String::from_utf8_lossy(value)))
}
