//! Which `Authentication-Results` header a verdict may be read from: the trust decision shared
//! by the `auth_results` and `verdict_*` columns and the verdict predicates.

use mboxturbo_headers::{
    AuthMethod, AuthenticationResults, Issue, ResInfo, TrustSet, TrustStatus,
    parse_authentication_results, parse_received_hops,
};

/// The `Authentication-Results` header name, lowercase.
pub(crate) const AUTHENTICATION_RESULTS: &str = "authentication-results";

/// The `Received` header name, lowercase.
pub(crate) const RECEIVED: &str = "received";

/// One `Authentication-Results` header with the trust its authserv-id and position earn.
pub(crate) struct DecidedResults<'mail> {
    /// The issues the parse reported.
    issues: Vec<Issue>,
    /// The parsed header.
    results: AuthenticationResults<'mail>,
    /// Whether the header is trusted, from [`decide_status`].
    status: TrustStatus,
}

impl<'mail> DecidedResults<'mail> {
    /// The issues the parse reported.
    pub(crate) fn issues(&self) -> &[Issue] {
        &self.issues
    }

    /// The parsed header.
    pub(crate) const fn results(&self) -> &AuthenticationResults<'mail> {
        &self.results
    }

    /// Whether the header is trusted.
    pub(crate) const fn status(&self) -> TrustStatus {
        self.status
    }
}

/// Every `Authentication-Results` header of `mail` in header order, each with its trust.
///
/// The one place that decides trust for the `auth_results` flag and the verdict columns.
pub(crate) fn decide_results<'bytes>(
    headers: impl IntoIterator<Item = (&'bytes [u8], &'bytes [u8])>,
    trust: Option<&TrustSet>,
) -> Vec<DecidedResults<'bytes>> {
    let mut received = Vec::new();
    let mut parsed = Vec::new();
    for (position, (name, value)) in headers.into_iter().enumerate() {
        if name.eq_ignore_ascii_case(AUTHENTICATION_RESULTS.as_bytes()) {
            let (results, issues) = parse_authentication_results(value, trust).into_parts();
            parsed.push((position, results, issues));
            continue;
        }
        if name.eq_ignore_ascii_case(RECEIVED.as_bytes()) {
            received.push((position, value));
        }
    }
    let any_idless = parsed
        .iter()
        .any(|(_, results, _)| results.authserv_id().is_empty());
    let boundary = trust
        .filter(|set| any_idless && set.trusts_idless_inside())
        .and_then(|set| first_external_position(&received, set));
    parsed
        .into_iter()
        .map(|(position, results, issues)| DecidedResults {
            status: decide_status(&results, position, trust, boundary),
            issues,
            results,
        })
        .collect()
}

/// The first `method` entry of the topmost trusted header in `decided` that has one.
pub(crate) fn trusted_entry<'decided, 'mail>(
    decided: &'decided [DecidedResults<'mail>],
    method: &AuthMethod<'_>,
) -> Option<&'decided ResInfo<'mail>> {
    decided
        .iter()
        .filter(|header| header.status() == TrustStatus::Trusted)
        .find_map(|header| {
            header
                .results()
                .entries()
                .iter()
                .find(|entry| entry.method() == method)
        })
}

/// Whether the topmost trusted `Authentication-Results` entry for `method` among `headers`
/// (name and raw value pairs, in order) reads `word`, as [`VerdictColumn`] would write it.
///
/// Only `Authentication-Results` and `Received` headers are read; other pairs are ignored.
/// Without a trust set nothing is trusted, so the answer is `false`.
pub(crate) fn verdict_is<'bytes>(
    headers: impl IntoIterator<Item = (&'bytes [u8], &'bytes [u8])>,
    method: &AuthMethod<'_>,
    trust: Option<&TrustSet>,
    word: &str,
) -> bool {
    let decided = decide_results(headers, trust);
    trusted_entry(&decided, method).is_some_and(|entry| entry.result().name() == word)
}

/// The trust of `results`, which sits at header `position`: by authserv-id as the parser says,
/// except that an id-less header is trusted when the set opts in, a first external hop exists
/// at header position `boundary` and the header sits above it.
fn decide_status(
    results: &AuthenticationResults<'_>,
    position: usize,
    trust: Option<&TrustSet>,
    boundary: Option<usize>,
) -> TrustStatus {
    match trust {
        Some(set) if results.authserv_id().is_empty() && set.trusts_idless_inside() => {
            if boundary.is_some_and(|external| position < external) {
                TrustStatus::Trusted
            } else {
                TrustStatus::Untrusted
            }
        },
        _ => results.trust(),
    }
}

/// The header position of the `Received` header of the first external hop, when there is one.
/// `received` holds the position and raw value of every `Received` header in header order.
fn first_external_position(received: &[(usize, &[u8])], trust: &TrustSet) -> Option<usize> {
    let values: Vec<&[u8]> = received.iter().map(|&(_, value)| value).collect();
    let (chain, _issues) = parse_received_hops(&values, Some(trust)).into_parts();
    let hop = chain.hops().get(chain.first_external()?)?;
    received
        .get(hop.header_index())
        .map(|&(position, _)| position)
}
