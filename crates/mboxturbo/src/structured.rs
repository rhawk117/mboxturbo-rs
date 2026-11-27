//! Nested Arrow columns for the parsed `Authentication-Results`, ARC and `DKIM-Signature`
//! headers. The field layouts are defined here once and documented on the `Column` variants.

mod received;

use std::sync::Arc;

use arrow_array::builder::{
    BooleanBuilder, ListBuilder, NullBuilder, StringBuilder, UInt8Builder, UInt32Builder,
    UInt64Builder,
};
use arrow_array::{Array as _, ArrayRef, ListArray, StructArray};
use arrow_schema::{ArrowError, DataType, Field, FieldRef, Fields};
use mboxturbo_headers::{
    ArcHeader, ArcSet, AuthMethod, AuthResult, AuthenticationResults, ChainValidation,
    DkimSignature, Issue, IssueKind, ResInfo, Tag, TagList, TrustSet, TrustStatus, parse_arc_sets,
    parse_authentication_results, parse_dkim_signature, parse_received_hops,
};
pub(crate) use received::{
    MicrosoftAntispamColumn, ReceivedHopsColumn, ReceivedSpfColumn, microsoft_antispam_type,
    received_hops_type, received_spf_parsed_type,
};

use crate::fields::Mail;
use crate::width::widen;

/// The `ARC-Authentication-Results` header name, lowercase.
const ARC_AUTHENTICATION_RESULTS: &str = "arc-authentication-results";

/// The `ARC-Message-Signature` header name, lowercase.
const ARC_MESSAGE_SIGNATURE: &str = "arc-message-signature";

/// The `ARC-Seal` header name, lowercase.
const ARC_SEAL: &str = "arc-seal";

/// The `Authentication-Results` header name, lowercase.
const AUTHENTICATION_RESULTS: &str = "authentication-results";

/// The `Received` header name, lowercase.
const RECEIVED: &str = "received";

/// The tags of a DKIM signature that have a column of their own, so `tags` leaves them out.
const DKIM_NAMED_TAGS: [&str; 7] = ["v", "a", "bh", "d", "h", "s", "b"];

/// The `DKIM-Signature` header name, lowercase.
const DKIM_SIGNATURE: &str = "dkim-signature";

/// The offsets and validity of a column of lists, built with Arrow's own list builder so the
/// offset buffer is validated there; the values arrive separately, already assembled.
#[derive(Debug)]
struct Shape(ListBuilder<NullBuilder>);

impl Shape {
    /// An empty shape.
    fn new() -> Self {
        Self(ListBuilder::new(NullBuilder::new()))
    }

    /// Records one valid list of `len` items.
    fn push_list(&mut self, len: usize) {
        self.0.values().append_nulls(len);
        self.0.append(true);
    }

    /// Records one null list.
    fn push_null(&mut self) {
        self.0.append(false);
    }

    /// The recorded lists over `values`, whose length must equal the items recorded.
    ///
    /// # Errors
    ///
    /// The Arrow error when `values` does not fit the recorded offsets or `item`.
    fn wrap(&mut self, item: FieldRef, values: ArrayRef) -> Result<ArrayRef, ArrowError> {
        let (_, offsets, _, nulls) = self.0.finish().into_parts();
        Ok(Arc::new(ListArray::try_new(item, offsets, values, nulls)?))
    }
}

/// One list of `{kind, offset}` issues per element.
#[derive(Debug)]
struct IssueLists {
    /// Issue kind names.
    kind: StringBuilder,
    /// Byte offsets into the header value.
    offset: UInt64Builder,
    /// List boundaries.
    shape: Shape,
}

impl IssueLists {
    /// The issue lists, as an Arrow array with one list per element pushed.
    ///
    /// # Errors
    ///
    /// The Arrow error when the issue arrays do not fit [`issue_fields`].
    fn finish(&mut self) -> Result<ArrayRef, ArrowError> {
        let values = StructArray::try_new(
            issue_fields(),
            vec![Arc::new(self.kind.finish()), Arc::new(self.offset.finish())],
            None,
        )?;
        self.shape
            .wrap(struct_item(issue_fields()), Arc::new(values))
    }

    /// Empty issue lists.
    fn new() -> Self {
        Self {
            kind: StringBuilder::new(),
            offset: UInt64Builder::new(),
            shape: Shape::new(),
        }
    }

    /// Appends one list holding `issues`.
    fn push<'issue>(&mut self, issues: impl Iterator<Item = &'issue Issue>) {
        let mut len = 0_usize;
        for issue in issues {
            self.kind.append_value(issue_kind_name(issue.kind()));
            self.offset.append_value(widen(issue.offset()));
            len = len.saturating_add(1);
        }
        self.shape.push_list(len);
    }
}

/// One nullable list of `{name, value, offset}` tags per element.
#[derive(Debug)]
struct TagLists {
    /// Tag names.
    name: StringBuilder,
    /// Byte offsets of the tags into the header value.
    offset: UInt64Builder,
    /// List boundaries.
    shape: Shape,
    /// Tag values.
    value: StringBuilder,
}

impl TagLists {
    /// The tag lists, as an Arrow array with one list per element pushed.
    ///
    /// # Errors
    ///
    /// The Arrow error when the tag arrays do not fit [`tag_fields`].
    fn finish(&mut self) -> Result<ArrayRef, ArrowError> {
        let values = StructArray::try_new(
            tag_fields(),
            vec![
                Arc::new(self.name.finish()),
                Arc::new(self.value.finish()),
                Arc::new(self.offset.finish()),
            ],
            None,
        )?;
        self.shape.wrap(struct_item(tag_fields()), Arc::new(values))
    }

    /// Empty tag lists.
    fn new() -> Self {
        Self {
            name: StringBuilder::new(),
            offset: UInt64Builder::new(),
            shape: Shape::new(),
            value: StringBuilder::new(),
        }
    }

    /// Appends one list holding `tags`.
    fn push<'tag, 'src>(&mut self, tags: impl Iterator<Item = &'tag Tag<'src>>)
    where
        'src: 'tag,
    {
        let mut len = 0_usize;
        for tag in tags {
            self.name.append_value(tag.name());
            self.value.append_value(tag.value());
            self.offset.append_value(widen(tag.offset()));
            len = len.saturating_add(1);
        }
        self.shape.push_list(len);
    }

    /// Appends a null list, for a header the set lacks.
    fn push_null(&mut self) {
        self.shape.push_null();
    }
}

/// One list of `{ptype, property, value}` per method result.
#[derive(Debug)]
struct PropertyLists {
    /// Property names.
    property: StringBuilder,
    /// Property types.
    ptype: StringBuilder,
    /// List boundaries.
    shape: Shape,
    /// Property values.
    value: StringBuilder,
}

impl PropertyLists {
    /// The property lists, as an Arrow array with one list per method result pushed.
    ///
    /// # Errors
    ///
    /// The Arrow error when the property arrays do not fit [`property_fields`].
    fn finish(&mut self) -> Result<ArrayRef, ArrowError> {
        let values = StructArray::try_new(
            property_fields(),
            vec![
                Arc::new(self.ptype.finish()),
                Arc::new(self.property.finish()),
                Arc::new(self.value.finish()),
            ],
            None,
        )?;
        self.shape
            .wrap(struct_item(property_fields()), Arc::new(values))
    }

    /// Empty property lists.
    fn new() -> Self {
        Self {
            property: StringBuilder::new(),
            ptype: StringBuilder::new(),
            shape: Shape::new(),
            value: StringBuilder::new(),
        }
    }

    /// Appends one list holding the properties of `entry`.
    fn push(&mut self, entry: &ResInfo<'_>) {
        for property in entry.properties() {
            self.ptype.append_value(property.ptype());
            self.property.append_value(property.property());
            self.value.append_value(property.value());
        }
        self.shape.push_list(entry.properties().len());
    }
}

/// One list of method results per `Authentication-Results` value.
#[derive(Debug)]
struct EntryLists {
    /// Method names.
    method: StringBuilder,
    /// Properties of each result.
    properties: PropertyLists,
    /// Reasons, null when absent.
    reason: StringBuilder,
    /// Result names.
    result: StringBuilder,
    /// List boundaries.
    shape: Shape,
}

impl EntryLists {
    /// The entry lists, as an Arrow array with one list per value pushed.
    ///
    /// # Errors
    ///
    /// The Arrow error when the entry arrays do not fit [`entry_fields`].
    fn finish(&mut self) -> Result<ArrayRef, ArrowError> {
        let values = StructArray::try_new(
            entry_fields(),
            vec![
                Arc::new(self.method.finish()),
                Arc::new(self.result.finish()),
                Arc::new(self.reason.finish()),
                self.properties.finish()?,
            ],
            None,
        )?;
        self.shape
            .wrap(struct_item(entry_fields()), Arc::new(values))
    }

    /// Empty entry lists.
    fn new() -> Self {
        Self {
            method: StringBuilder::new(),
            properties: PropertyLists::new(),
            reason: StringBuilder::new(),
            result: StringBuilder::new(),
            shape: Shape::new(),
        }
    }

    /// Appends one list holding `entries`.
    fn push(&mut self, entries: &[ResInfo<'_>]) {
        for entry in entries {
            self.method.append_value(method_name(entry.method()));
            self.result.append_value(result_name(entry.result()));
            self.reason.append_option(entry.reason());
            self.properties.push(entry);
        }
        self.shape.push_list(entries.len());
    }
}

/// The columns of parsed `Authentication-Results` values, one row per value.
#[derive(Debug)]
struct ResultsRows {
    /// Authserv-ids.
    authserv_id: StringBuilder,
    /// Method results of each value.
    entries: EntryLists,
    /// Whether each row came from a header; false rows make the struct null.
    present: BooleanBuilder,
    /// Trust flags.
    trusted: BooleanBuilder,
    /// Version numbers.
    version: UInt32Builder,
}

impl ResultsRows {
    /// The arrays of [`results_fields`].
    ///
    /// # Errors
    ///
    /// The Arrow error when the entry arrays do not fit their layout.
    fn finish_columns(&mut self) -> Result<Vec<ArrayRef>, ArrowError> {
        Ok(vec![
            Arc::new(self.authserv_id.finish()),
            Arc::new(self.version.finish()),
            self.entries.finish()?,
            Arc::new(self.trusted.finish()),
        ])
    }

    /// The rows as a struct array, null where the header was absent.
    ///
    /// # Errors
    ///
    /// The Arrow error when the arrays do not fit [`results_fields`].
    fn finish_struct(&mut self) -> Result<ArrayRef, ArrowError> {
        let nulls = self.present.finish().nulls().cloned();
        let columns = self.finish_columns()?;
        Ok(Arc::new(StructArray::try_new(
            results_fields(),
            columns,
            nulls,
        )?))
    }

    /// Empty rows.
    fn new() -> Self {
        Self {
            authserv_id: StringBuilder::new(),
            entries: EntryLists::new(),
            present: BooleanBuilder::new(),
            trusted: BooleanBuilder::new(),
            version: UInt32Builder::new(),
        }
    }

    /// Appends the row for `results`, flagged by `status`.
    fn push(&mut self, results: &AuthenticationResults<'_>, status: TrustStatus) {
        self.authserv_id.append_value(results.authserv_id());
        self.version.append_option(results.version());
        self.entries.push(results.entries());
        self.trusted.append_option(trusted(status));
        self.present.append_value(true);
    }

    /// Appends a row for a header that is absent: every field null, the entries empty.
    fn push_absent(&mut self) {
        self.authserv_id.append_null();
        self.version.append_null();
        self.entries.push(&[]);
        self.trusted.append_null();
        self.present.append_null();
    }
}

/// Builder of the `auth_results` column.
#[derive(Debug)]
pub(crate) struct AuthResultsColumn {
    /// Issues of each value.
    issues: IssueLists,
    /// The parsed values.
    results: ResultsRows,
    /// Message boundaries.
    shape: Shape,
}

impl AuthResultsColumn {
    /// Appends the list of every `Authentication-Results` header of `mail`, parsed from its raw
    /// bytes in header order; an unparsed message appends an empty list.
    pub(crate) fn append(&mut self, mail: Option<&Mail<'_>>, trust: Option<&TrustSet>) {
        let decided = mail.map_or_else(Vec::new, |parsed| {
            decide_results(mail_headers(parsed), trust)
        });
        for header in &decided {
            self.results.push(&header.results, header.status);
            self.issues.push(header.issues.iter());
        }
        self.shape.push_list(decided.len());
    }

    /// The column, as an Arrow array with one list per message appended.
    ///
    /// # Errors
    ///
    /// The Arrow error when the nested arrays do not fit [`auth_results_fields`].
    pub(crate) fn finish(&mut self) -> Result<ArrayRef, ArrowError> {
        let mut columns = self.results.finish_columns()?;
        columns.push(self.issues.finish()?);
        let values = StructArray::try_new(auth_results_fields(), columns, None)?;
        self.shape
            .wrap(struct_item(auth_results_fields()), Arc::new(values))
    }

    /// An empty column.
    pub(crate) fn new() -> Self {
        Self {
            issues: IssueLists::new(),
            results: ResultsRows::new(),
            shape: Shape::new(),
        }
    }
}

/// Builder of the `arc_sets` column.
#[derive(Debug)]
pub(crate) struct ArcSetsColumn {
    /// The seal's `cv` tag.
    chain_validation: StringBuilder,
    /// Instance numbers.
    instance: UInt8Builder,
    /// Every issue of each message's chain.
    issues: IssueLists,
    /// `ARC-Message-Signature` tags.
    message_signature: TagLists,
    /// `ARC-Authentication-Results` of each set.
    results: ResultsRows,
    /// `ARC-Seal` tags.
    seal: TagLists,
    /// Set boundaries of each message.
    shape: Shape,
}

impl ArcSetsColumn {
    /// Appends the ARC sets and chain issues of `mail`, parsed from the raw bytes of its ARC
    /// headers; an unparsed message appends an empty list of each.
    pub(crate) fn append(&mut self, mail: Option<&Mail<'_>>, trust: Option<&TrustSet>) {
        let headers: Vec<ArcHeader<'_>> = mail.into_iter().flat_map(arc_headers).collect();
        let (sets, issues) = parse_arc_sets(&headers, trust).into_parts();
        for set in &sets {
            self.push_set(set);
        }
        self.shape.push_list(sets.len());
        self.issues.push(issues.iter());
    }

    /// The column, as an Arrow struct array holding the `{sets, issues}` of every message appended.
    ///
    /// # Errors
    ///
    /// The Arrow error when the nested arrays do not fit [`arc_set_fields`] or
    /// [`arc_sets_fields`].
    pub(crate) fn finish(&mut self) -> Result<ArrayRef, ArrowError> {
        let columns: Vec<ArrayRef> = vec![
            Arc::new(self.instance.finish()),
            self.seal.finish()?,
            self.message_signature.finish()?,
            self.results.finish_struct()?,
            Arc::new(self.chain_validation.finish()),
        ];
        let values = StructArray::try_new(arc_set_fields(), columns, None)?;
        let sets = self
            .shape
            .wrap(struct_item(arc_set_fields()), Arc::new(values))?;
        Ok(Arc::new(StructArray::try_new(
            arc_sets_fields(),
            vec![sets, self.issues.finish()?],
            None,
        )?))
    }

    /// An empty column.
    pub(crate) fn new() -> Self {
        Self {
            chain_validation: StringBuilder::new(),
            instance: UInt8Builder::new(),
            issues: IssueLists::new(),
            message_signature: TagLists::new(),
            results: ResultsRows::new(),
            seal: TagLists::new(),
            shape: Shape::new(),
        }
    }

    /// Appends the row for `set`.
    fn push_set(&mut self, set: &ArcSet<'_>) {
        self.instance.append_value(set.instance());
        push_optional_tags(&mut self.seal, set.seal().map(TagList::tags));
        push_optional_tags(
            &mut self.message_signature,
            set.message_signature().map(TagList::tags),
        );
        match set.authentication_results() {
            Some(results) => self.results.push(results, results.trust()),
            None => self.results.push_absent(),
        }
        self.chain_validation
            .append_option(set.chain_validation().as_ref().map(chain_validation_name));
    }
}

/// Builder of the `dkim_signatures` column.
#[derive(Debug)]
pub(crate) struct DkimSignaturesColumn {
    /// The `a` tags.
    algorithm: StringBuilder,
    /// The `bh` tags.
    body_hash: StringBuilder,
    /// The `d` tags.
    domain: StringBuilder,
    /// Issues of each signature.
    issues: IssueLists,
    /// The `s` tags.
    selector: StringBuilder,
    /// Message boundaries.
    shape: Shape,
    /// The `b` tags.
    signature: StringBuilder,
    /// The `h` tags split into header names.
    signed_headers: ListBuilder<StringBuilder>,
    /// The tags without a column of their own.
    tags: TagLists,
    /// The `v` tags.
    version: StringBuilder,
}

impl DkimSignaturesColumn {
    /// Appends the list of every `DKIM-Signature` header of `mail`, parsed from its raw bytes in
    /// header order; an unparsed message appends an empty list.
    pub(crate) fn append(&mut self, mail: Option<&Mail<'_>>) {
        let mut len = 0_usize;
        for value in mail
            .into_iter()
            .flat_map(|parsed| raw_values(parsed, DKIM_SIGNATURE))
        {
            let (signature, issues) = parse_dkim_signature(value).into_parts();
            self.push_signature(&signature);
            self.issues.push(issues.iter());
            len = len.saturating_add(1);
        }
        self.shape.push_list(len);
    }

    /// The column, as an Arrow array with one list per message appended.
    ///
    /// # Errors
    ///
    /// The Arrow error when the nested arrays do not fit [`dkim_fields`].
    pub(crate) fn finish(&mut self) -> Result<ArrayRef, ArrowError> {
        let columns: Vec<ArrayRef> = vec![
            Arc::new(self.version.finish()),
            Arc::new(self.algorithm.finish()),
            Arc::new(self.body_hash.finish()),
            Arc::new(self.domain.finish()),
            Arc::new(self.selector.finish()),
            Arc::new(self.signature.finish()),
            Arc::new(self.signed_headers.finish()),
            self.tags.finish()?,
            self.issues.finish()?,
        ];
        let values = StructArray::try_new(dkim_fields(), columns, None)?;
        self.shape
            .wrap(struct_item(dkim_fields()), Arc::new(values))
    }

    /// An empty column.
    pub(crate) fn new() -> Self {
        Self {
            algorithm: StringBuilder::new(),
            body_hash: StringBuilder::new(),
            domain: StringBuilder::new(),
            issues: IssueLists::new(),
            selector: StringBuilder::new(),
            shape: Shape::new(),
            signature: StringBuilder::new(),
            signed_headers: ListBuilder::new(StringBuilder::new()).with_field(text_item()),
            tags: TagLists::new(),
            version: StringBuilder::new(),
        }
    }

    /// Appends the row for `signature`, without its issues.
    fn push_signature(&mut self, signature: &DkimSignature<'_>) {
        self.version.append_option(signature.version());
        self.algorithm.append_option(signature.algorithm());
        self.body_hash.append_option(signature.body_hash());
        self.domain.append_option(signature.domain());
        self.selector.append_option(signature.selector());
        self.signature.append_option(signature.signature());
        self.signed_headers
            .values()
            .extend(signature.signed_headers().map(Some));
        self.signed_headers.append(true);
        let others = signature
            .tags()
            .tags()
            .iter()
            .filter(|tag| !DKIM_NAMED_TAGS.contains(&tag.name()));
        self.tags.push(others);
    }
}

/// One `Authentication-Results` header with the trust its authserv-id and position earn.
struct DecidedResults<'mail> {
    /// The issues the parse reported.
    issues: Vec<Issue>,
    /// The parsed header.
    results: AuthenticationResults<'mail>,
    /// Whether the header is trusted, from [`decide_status`].
    status: TrustStatus,
}

/// Builder of one `verdict_*` column.
#[derive(Debug)]
pub(crate) struct VerdictColumn {
    /// The values appended so far.
    builder: StringBuilder,
    /// The method whose result is read.
    method: AuthMethod<'static>,
}

impl VerdictColumn {
    /// Appends the result word of the first `method` entry in the topmost trusted
    /// `Authentication-Results` of `mail` that has one; null when there is none, the message is
    /// unparsed or no trust set was given.
    pub(crate) fn append(&mut self, mail: Option<&Mail<'_>>, trust: Option<&TrustSet>) {
        let decided = mail.map_or_else(Vec::new, |parsed| {
            decide_results(mail_headers(parsed), trust)
        });
        let verdict = trusted_entry(&decided, &self.method);
        self.builder
            .append_option(verdict.map(|entry| result_name(entry.result())));
    }

    /// The column built so far, resetting the builder.
    pub(crate) fn finish(&mut self) -> ArrayRef {
        Arc::new(self.builder.finish())
    }

    /// An empty column reading `method`.
    pub(crate) fn new(method: AuthMethod<'static>) -> Self {
        Self {
            builder: StringBuilder::new(),
            method,
        }
    }
}

/// The Arrow type of the `arc_sets` column.
pub(crate) fn arc_sets_type() -> DataType {
    DataType::Struct(arc_sets_fields())
}

/// The Arrow type of the `auth_results` column.
pub(crate) fn auth_results_type() -> DataType {
    list_of_structs(auth_results_fields())
}

/// The Arrow type of the `dkim_signatures` column.
pub(crate) fn dkim_signatures_type() -> DataType {
    list_of_structs(dkim_fields())
}

/// The ARC headers of `mail` in header order, tagged with their kind.
fn arc_headers<'mail>(mail: &'mail Mail<'mail>) -> impl Iterator<Item = ArcHeader<'mail>> {
    mail.headers().iter().filter_map(|header| {
        let header_name = header.name();
        let name = header_name.as_str();
        let value = strip_line_break(header.raw_value());
        if name.eq_ignore_ascii_case(ARC_AUTHENTICATION_RESULTS) {
            Some(ArcHeader::AuthenticationResults(value))
        } else if name.eq_ignore_ascii_case(ARC_MESSAGE_SIGNATURE) {
            Some(ArcHeader::MessageSignature(value))
        } else if name.eq_ignore_ascii_case(ARC_SEAL) {
            Some(ArcHeader::Seal(value))
        } else {
            None
        }
    })
}

/// The struct of one `arc_sets` element.
fn arc_set_fields() -> Fields {
    Fields::from(vec![
        field("instance", DataType::UInt8),
        struct_list_field("seal", tag_fields()),
        struct_list_field("message_signature", tag_fields()),
        field("authentication_results", DataType::Struct(results_fields())),
        field("chain_validation", DataType::Utf8),
    ])
}

/// The struct of one `arc_sets` value: the sets plus the issues of the whole chain.
fn arc_sets_fields() -> Fields {
    Fields::from(vec![
        struct_list_field("sets", arc_set_fields()),
        struct_list_field("issues", issue_fields()),
    ])
}

/// The struct of one `auth_results` element: the results plus their issues.
fn auth_results_fields() -> Fields {
    with_issues(&results_fields())
}

/// The `cv=` text of a seal, lowercase for the known statuses.
fn chain_validation_name<'status>(status: &'status ChainValidation<'_>) -> &'status str {
    match status {
        ChainValidation::Fail => "fail",
        ChainValidation::None => "none",
        ChainValidation::Other(text) => text,
        ChainValidation::Pass => "pass",
        _ => "unknown",
    }
}

/// Every `Authentication-Results` header of `mail` in header order, each with its trust.
///
/// The one place that decides trust for the `auth_results` flag and the verdict columns.
fn decide_results<'bytes>(
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
fn trusted_entry<'decided, 'mail>(
    decided: &'decided [DecidedResults<'mail>],
    method: &AuthMethod<'_>,
) -> Option<&'decided ResInfo<'mail>> {
    decided
        .iter()
        .filter(|header| header.status == TrustStatus::Trusted)
        .find_map(|header| {
            header
                .results
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
    trusted_entry(&decided, method).is_some_and(|entry| result_name(entry.result()) == word)
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

/// The struct of one `dkim_signatures` element.
fn dkim_fields() -> Fields {
    with_issues(&Fields::from(vec![
        field("version", DataType::Utf8),
        field("algorithm", DataType::Utf8),
        field("body_hash", DataType::Utf8),
        field("domain", DataType::Utf8),
        field("selector", DataType::Utf8),
        field("signature", DataType::Utf8),
        field("signed_headers", DataType::List(text_item())),
        struct_list_field("tags", tag_fields()),
    ]))
}

/// The struct of one method result of an `Authentication-Results` header.
fn entry_fields() -> Fields {
    Fields::from(vec![
        field("method", DataType::Utf8),
        field("result", DataType::Utf8),
        field("reason", DataType::Utf8),
        struct_list_field("properties", property_fields()),
    ])
}

/// A nullable field named `name` of `data_type`.
fn field(name: &str, data_type: DataType) -> Field {
    Field::new(name, data_type, true)
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

/// The `{kind, offset}` struct of one issue.
fn issue_fields() -> Fields {
    Fields::from(vec![
        field("kind", DataType::Utf8),
        field("offset", DataType::UInt64),
    ])
}

/// A stable `snake_case` name for each kind of issue.
///
/// A kind added to the headers crate after this was written reads `unknown` until someone gives
/// it a name in this function.
const fn issue_kind_name(kind: IssueKind) -> &'static str {
    match kind {
        IssueKind::ArcInstance { .. } => "arc_instance",
        IssueKind::AssumedZone => "assumed_zone",
        IssueKind::CapExceeded { .. } => "cap_exceeded",
        IssueKind::InvalidEncoding => "invalid_encoding",
        IssueKind::InvalidUtf8 => "invalid_utf8",
        IssueKind::MalformedBytes => "malformed_bytes",
        IssueKind::MalformedEntry => "malformed_entry",
        IssueKind::MissingTag { .. } => "missing_tag",
        IssueKind::NegativeDelay => "negative_delay",
        IssueKind::OutOfRange => "out_of_range",
        IssueKind::RepeatedTag => "repeated_tag",
        IssueKind::TrailingText => "trailing_text",
        IssueKind::UnknownCharset => "unknown_charset",
        IssueKind::UnparsableDate => "unparsable_date",
        IssueKind::UnterminatedComment => "unterminated_comment",
        IssueKind::UnterminatedQuote => "unterminated_quote",
        IssueKind::WeekdayMismatch => "weekday_mismatch",
        IssueKind::WidenedYear => "widened_year",
        _ => "unknown",
    }
}

/// A list whose items are structs of `fields`.
fn list_of_structs(fields: Fields) -> DataType {
    DataType::List(struct_item(fields))
}

/// The method name as written in the header, lowercase for the known methods.
fn method_name<'method>(method: &'method AuthMethod<'_>) -> &'method str {
    match method {
        AuthMethod::Arc => "arc",
        AuthMethod::Auth => "auth",
        AuthMethod::CompAuth => "compauth",
        AuthMethod::Dkim => "dkim",
        AuthMethod::Dmarc => "dmarc",
        AuthMethod::DomainKeys => "domainkeys",
        AuthMethod::Iprev => "iprev",
        AuthMethod::Other(name) => name,
        AuthMethod::SenderId => "sender-id",
        AuthMethod::Spf => "spf",
        _ => "unknown",
    }
}

/// The `{ptype, property, value}` struct of one result property.
fn property_fields() -> Fields {
    Fields::from(vec![
        field("ptype", DataType::Utf8),
        field("property", DataType::Utf8),
        field("value", DataType::Utf8),
    ])
}

/// Appends `tags` as one list, or a null list when the set lacks the header.
fn push_optional_tags(lists: &mut TagLists, tags: Option<&[Tag<'_>]>) {
    match tags {
        Some(present) => lists.push(present.iter()),
        None => lists.push_null(),
    }
}

/// The raw value of every header called `name` in `mail`, in header order, without the final
/// line break.
fn raw_values<'mail>(
    mail: &'mail Mail<'mail>,
    name: &'static str,
) -> impl Iterator<Item = &'mail [u8]> {
    mail.headers()
        .iter()
        .filter(move |header| header.name().as_str().eq_ignore_ascii_case(name))
        .map(|header| strip_line_break(header.raw_value()))
}

/// The name and raw value of every header of `mail` in header order; the value has no final
/// line break.
fn mail_headers<'mail>(
    mail: &'mail Mail<'mail>,
) -> impl Iterator<Item = (&'mail [u8], &'mail [u8])> {
    mail.headers().iter().map(|header| {
        (
            header.raw_name().as_bytes(),
            strip_line_break(header.raw_value()),
        )
    })
}

/// The fields of one parsed `Authentication-Results` value, without its issues.
fn results_fields() -> Fields {
    Fields::from(vec![
        field("authserv_id", DataType::Utf8),
        field("version", DataType::UInt32),
        struct_list_field("entries", entry_fields()),
        field("trusted", DataType::Boolean),
    ])
}

/// The result name as written in the header, lowercase for the known results.
fn result_name<'result>(result: &'result AuthResult<'_>) -> &'result str {
    match result {
        AuthResult::Fail => "fail",
        AuthResult::Neutral => "neutral",
        AuthResult::NoResult => "none",
        AuthResult::Other(name) => name,
        AuthResult::Pass => "pass",
        AuthResult::PermError => "permerror",
        AuthResult::Policy => "policy",
        AuthResult::SoftFail => "softfail",
        AuthResult::TempError => "temperror",
        AuthResult::Unknown | _ => "unknown",
    }
}

/// `raw` without its one final line break.
fn strip_line_break(raw: &[u8]) -> &[u8] {
    raw.strip_suffix(b"\r\n")
        .or_else(|| raw.strip_suffix(b"\n"))
        .unwrap_or(raw)
}

/// The nullable list item field holding a struct of `fields`.
fn struct_item(fields: Fields) -> FieldRef {
    Arc::new(Field::new("item", DataType::Struct(fields), true))
}

/// A nullable field named `name` holding a list of structs of `fields`.
fn struct_list_field(name: &str, fields: Fields) -> Field {
    field(name, list_of_structs(fields))
}

/// The `{name, value, offset}` struct of one tag.
fn tag_fields() -> Fields {
    Fields::from(vec![
        field("name", DataType::Utf8),
        field("value", DataType::Utf8),
        field("offset", DataType::UInt64),
    ])
}

/// The nullable list item field holding text.
fn text_item() -> FieldRef {
    Arc::new(Field::new("item", DataType::Utf8, true))
}

/// `Some(true)` for a trusted authserv-id, `Some(false)` for an untrusted one and `None` when no
/// trust set was given.
const fn trusted(status: TrustStatus) -> Option<bool> {
    match status {
        TrustStatus::Trusted => Some(true),
        TrustStatus::Untrusted => Some(false),
        TrustStatus::Unknown | _ => None,
    }
}

/// `fields` followed by the `issues` list every element carries.
fn with_issues(fields: &Fields) -> Fields {
    fields
        .iter()
        .cloned()
        .chain([Arc::new(struct_list_field("issues", issue_fields()))])
        .collect()
}
