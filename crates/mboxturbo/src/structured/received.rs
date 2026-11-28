//! Nested Arrow columns for the parsed `Received` chain, `Received-SPF` and Microsoft antispam
//! headers. The field layouts are defined here once and documented on the `Column` variants.

use std::sync::Arc;

use arrow_array::builder::{
    BooleanBuilder, Int8Builder, Int32Builder, Int64Builder, StringBuilder,
    TimestampMicrosecondBuilder, UInt8Builder, UInt64Builder,
};
use arrow_array::{Array as _, ArrayRef, StructArray};
use arrow_schema::{ArrowError, DataType, Fields, TimeUnit};
use mboxturbo_headers::{
    Hop, MsAntispam, ReceivedSpf, Tls, parse_ms_antispam, parse_received_hops, parse_received_spf,
};

use super::{
    IssueLists, Shape, field, issue_fields, list_of_structs, raw_values, strip_line_break,
    struct_item, struct_list_field, with_issues,
};
use crate::fields::Mail;
use crate::pipeline::{ColumnBuilder, Record};
use crate::verdict::RECEIVED;
use crate::width::widen;

/// The `Received-SPF` header name, lowercase.
const RECEIVED_SPF: &str = "received-spf";

/// The Microsoft antispam header names, lowercase.
const MS_ANTISPAM_HEADERS: [&str; 2] = ["x-forefront-antispam-report", "x-microsoft-antispam"];

/// The names of the text fields of a Microsoft antispam element, in the order of [`ms_texts`].
const MS_TEXT: [&str; 10] = [
    "category",
    "country",
    "direction",
    "helo",
    "ip_verdict",
    "language",
    "ptr",
    "safety",
    "service",
    "spam_verdict",
];

/// Microseconds per second.
const MICROS_PER_SECOND: i64 = 1_000_000;

/// One list of `{key, value, offset}` entries per element.
#[derive(Debug)]
struct PairLists {
    /// The key of each pair, as written before the separator.
    key: StringBuilder,
    /// Byte offsets of the keys into the header value.
    offset: UInt64Builder,
    /// List boundaries: which pairs belong to which element.
    shape: Shape,
    /// The value of each pair, as written after the separator; empty when the pair has none.
    value: StringBuilder,
}

impl PairLists {
    /// The pair lists, as an Arrow array with one list per element pushed.
    ///
    /// # Errors
    ///
    /// The Arrow error when the pair arrays do not fit [`pair_fields`].
    fn finish(&mut self) -> Result<ArrayRef, ArrowError> {
        let values = StructArray::try_new(
            pair_fields(),
            vec![
                Arc::new(self.key.finish()),
                Arc::new(self.value.finish()),
                Arc::new(self.offset.finish()),
            ],
            None,
        )?;
        self.shape
            .wrap(struct_item(pair_fields()), Arc::new(values))
    }

    /// Empty pair lists.
    fn new() -> Self {
        Self {
            key: StringBuilder::new(),
            offset: UInt64Builder::new(),
            shape: Shape::new(),
            value: StringBuilder::new(),
        }
    }

    /// Appends one list holding `pairs`, each a key, a value and the offset of the key.
    fn push<'pair>(&mut self, pairs: impl Iterator<Item = (&'pair str, &'pair str, usize)>) {
        let mut len = 0_usize;
        for (key, value, offset) in pairs {
            self.key.append_value(key);
            self.value.append_value(value);
            self.offset.append_value(widen(offset));
            len = len.saturating_add(1);
        }
        self.shape.push_list(len);
    }
}

/// The TLS details of the hops, one row per hop, null where the hop has none.
#[derive(Debug)]
struct TlsRows {
    /// Cipher suites.
    cipher: StringBuilder,
    /// Whether each hop had TLS details; null rows make the struct null.
    present: BooleanBuilder,
    /// Protocol versions.
    version: StringBuilder,
}

impl TlsRows {
    /// The rows as a struct array, null where the hop had no TLS details.
    ///
    /// # Errors
    ///
    /// The Arrow error when the arrays do not fit [`tls_fields`].
    fn finish(&mut self) -> Result<ArrayRef, ArrowError> {
        let nulls = self.present.finish().nulls().cloned();
        Ok(Arc::new(StructArray::try_new(
            tls_fields(),
            vec![
                Arc::new(self.version.finish()),
                Arc::new(self.cipher.finish()),
            ],
            nulls,
        )?))
    }

    /// Empty rows.
    fn new() -> Self {
        Self {
            cipher: StringBuilder::new(),
            present: BooleanBuilder::new(),
            version: StringBuilder::new(),
        }
    }

    /// Appends the row for `tls`.
    fn push(&mut self, tls: Option<&Tls<'_>>) {
        self.version.append_option(tls.map(Tls::version));
        self.cipher.append_option(tls.and_then(Tls::cipher));
        match tls {
            Some(_) => self.present.append_value(true),
            None => self.present.append_null(),
        }
    }
}

/// The hops of every message, one row per hop.
#[derive(Debug)]
struct HopRows {
    /// Hosts after `by`.
    by_host: StringBuilder,
    /// Dates as UTC microseconds.
    date: TimestampMicrosecondBuilder,
    /// Minutes east of UTC of each date.
    date_offset_minutes: Int32Builder,
    /// Seconds since the previous hop.
    delay_seconds: Int64Builder,
    /// Whether each hop is the first external one.
    first_external: BooleanBuilder,
    /// First comments of the `from` clauses.
    from_comment: StringBuilder,
    /// Hosts after `from`.
    from_host: StringBuilder,
    /// Positions of the headers.
    header_index: UInt64Builder,
    /// Queue ids.
    id: StringBuilder,
    /// Client addresses.
    ip: StringBuilder,
    /// Protocols after `with`.
    protocol: StringBuilder,
    /// Recipients after `for`.
    recipient: StringBuilder,
    /// TLS details.
    tls: TlsRows,
}

impl HopRows {
    /// The arrays of [`hop_fields`].
    ///
    /// # Errors
    ///
    /// The Arrow error when the TLS arrays do not fit their layout.
    fn finish(&mut self) -> Result<Vec<ArrayRef>, ArrowError> {
        Ok(vec![
            Arc::new(self.header_index.finish()),
            Arc::new(self.from_host.finish()),
            Arc::new(self.from_comment.finish()),
            Arc::new(self.ip.finish()),
            Arc::new(self.by_host.finish()),
            Arc::new(self.recipient.finish()),
            Arc::new(self.id.finish()),
            Arc::new(self.protocol.finish()),
            self.tls.finish()?,
            Arc::new(self.date.finish()),
            Arc::new(self.date_offset_minutes.finish()),
            Arc::new(self.delay_seconds.finish()),
            Arc::new(self.first_external.finish()),
        ])
    }

    /// Empty rows.
    fn new() -> Self {
        Self {
            by_host: StringBuilder::new(),
            date: TimestampMicrosecondBuilder::new().with_timezone("UTC"),
            date_offset_minutes: Int32Builder::new(),
            delay_seconds: Int64Builder::new(),
            first_external: BooleanBuilder::new(),
            from_comment: StringBuilder::new(),
            from_host: StringBuilder::new(),
            header_index: UInt64Builder::new(),
            id: StringBuilder::new(),
            ip: StringBuilder::new(),
            protocol: StringBuilder::new(),
            recipient: StringBuilder::new(),
            tls: TlsRows::new(),
        }
    }

    /// Appends the row for `hop`; `first_external` is null without a trust set.
    fn push(&mut self, hop: &Hop<'_>, first_external: Option<bool>) {
        self.header_index.append_value(widen(hop.header_index()));
        self.from_host.append_option(hop.from_host());
        self.from_comment.append_option(hop.from_comment());
        self.ip.append_option(hop.ip().map(|ip| ip.to_string()));
        self.by_host.append_option(hop.by_host());
        self.recipient.append_option(hop.recipient());
        self.id.append_option(hop.id());
        self.protocol.append_option(hop.protocol());
        self.tls.push(hop.tls());
        self.date.append_option(
            hop.date()
                .map(|date| date.unix_seconds().saturating_mul(MICROS_PER_SECOND)),
        );
        self.date_offset_minutes
            .append_option(hop.date().map(|date| i32::from(date.offset_minutes())));
        self.delay_seconds.append_option(hop.delay_seconds());
        self.first_external.append_option(first_external);
    }
}

/// Builder of the `received_hops` column.
#[derive(Debug)]
pub(crate) struct ReceivedHopsColumn {
    /// The hops of every message.
    hops: HopRows,
    /// Every issue of each message's chain.
    issues: IssueLists,
    /// Hop boundaries of each message.
    shape: Shape,
}

impl ReceivedHopsColumn {
    /// An empty column.
    pub(crate) fn new() -> Self {
        Self {
            hops: HopRows::new(),
            issues: IssueLists::new(),
            shape: Shape::new(),
        }
    }
}

impl ColumnBuilder for ReceivedHopsColumn {
    /// Appends the hop chain of `mail`, parsed from the raw bytes of every `Received` header in
    /// header order; an unparsed message appends an empty list of each.
    fn append(&mut self, record: &Record<'_>) {
        let mail = record.mail();
        let trust = record.trust();
        let headers: Vec<&[u8]> = mail
            .into_iter()
            .flat_map(|parsed| raw_values(parsed, RECEIVED))
            .collect();
        let (chain, issues) = parse_received_hops(&headers, trust).into_parts();
        for (index, hop) in chain.hops().iter().enumerate() {
            let external = trust.map(|_| chain.first_external() == Some(index));
            self.hops.push(hop, external);
        }
        self.shape.push_list(chain.hops().len());
        self.issues.push(issues.iter());
    }

    /// The column, as an Arrow struct array holding the `{hops, issues}` of every message appended.
    ///
    /// # Errors
    ///
    /// The Arrow error when the nested arrays do not fit [`hop_fields`] or
    /// [`received_hops_fields`].
    fn finish(&mut self) -> Result<ArrayRef, ArrowError> {
        let values = StructArray::try_new(hop_fields(), self.hops.finish()?, None)?;
        let hops = self
            .shape
            .wrap(struct_item(hop_fields()), Arc::new(values))?;
        Ok(Arc::new(StructArray::try_new(
            received_hops_fields(),
            vec![hops, self.issues.finish()?],
            None,
        )?))
    }
}

/// Builder of the `received_spf_parsed` column.
#[derive(Debug)]
pub(crate) struct ReceivedSpfColumn {
    /// The `client-ip` pairs.
    client_ip: StringBuilder,
    /// The first comments.
    comment: StringBuilder,
    /// Issues of each header.
    issues: IssueLists,
    /// The `key=value` pairs.
    pairs: PairLists,
    /// The verdict words.
    result: StringBuilder,
    /// Message boundaries.
    shape: Shape,
}

impl ReceivedSpfColumn {
    /// An empty column.
    pub(crate) fn new() -> Self {
        Self {
            client_ip: StringBuilder::new(),
            comment: StringBuilder::new(),
            issues: IssueLists::new(),
            pairs: PairLists::new(),
            result: StringBuilder::new(),
            shape: Shape::new(),
        }
    }

    /// Appends the row for `spf`, without its issues.
    fn push_header(&mut self, spf: &ReceivedSpf<'_>) {
        self.result.append_value(spf.result().name());
        self.client_ip
            .append_option(spf.client_ip().map(|ip| ip.to_string()));
        self.comment.append_option(spf.comment());
        self.pairs.push(
            spf.pairs()
                .iter()
                .map(|pair| (pair.key.as_ref(), pair.value.as_ref(), pair.offset)),
        );
    }
}

impl ColumnBuilder for ReceivedSpfColumn {
    /// Appends the list of every `Received-SPF` header of `mail`, parsed from its raw bytes in
    /// header order; an unparsed message appends an empty list.
    fn append(&mut self, record: &Record<'_>) {
        let mail = record.mail();
        let mut len = 0_usize;
        for value in mail
            .into_iter()
            .flat_map(|parsed| raw_values(parsed, RECEIVED_SPF))
        {
            let (spf, issues) = parse_received_spf(value).into_parts();
            self.push_header(&spf);
            self.issues.push(issues.iter());
            len = len.saturating_add(1);
        }
        self.shape.push_list(len);
    }

    /// The column, as an Arrow array with one list per message appended.
    ///
    /// # Errors
    ///
    /// The Arrow error when the nested arrays do not fit [`received_spf_fields`].
    fn finish(&mut self) -> Result<ArrayRef, ArrowError> {
        let columns: Vec<ArrayRef> = vec![
            Arc::new(self.result.finish()),
            Arc::new(self.client_ip.finish()),
            Arc::new(self.comment.finish()),
            self.pairs.finish()?,
            self.issues.finish()?,
        ];
        let values = StructArray::try_new(received_spf_fields(), columns, None)?;
        self.shape
            .wrap(struct_item(received_spf_fields()), Arc::new(values))
    }
}

/// Builder of the `microsoft_antispam` column.
#[derive(Debug)]
pub(crate) struct MicrosoftAntispamColumn {
    /// The `BCL` entries.
    bcl: UInt8Builder,
    /// The `CIP` entries.
    client_ip: StringBuilder,
    /// Every entry of each header.
    entries: PairLists,
    /// The header names.
    header: StringBuilder,
    /// Issues of each header.
    issues: IssueLists,
    /// The `SCL` entries.
    scl: Int8Builder,
    /// Message boundaries.
    shape: Shape,
    /// The text entries, in the order of [`MS_TEXT`].
    text: Vec<StringBuilder>,
}

impl MicrosoftAntispamColumn {
    /// An empty column.
    pub(crate) fn new() -> Self {
        Self {
            bcl: UInt8Builder::new(),
            client_ip: StringBuilder::new(),
            entries: PairLists::new(),
            header: StringBuilder::new(),
            issues: IssueLists::new(),
            scl: Int8Builder::new(),
            shape: Shape::new(),
            text: MS_TEXT.iter().map(|_| StringBuilder::new()).collect(),
        }
    }

    /// Appends the row for `antispam`, without its header name or issues.
    fn push_header(&mut self, antispam: &MsAntispam<'_>) {
        self.scl.append_option(antispam.scl());
        self.bcl.append_option(antispam.bcl());
        self.client_ip
            .append_option(antispam.client_ip().map(|ip| ip.to_string()));
        for (builder, text) in self.text.iter_mut().zip(ms_texts(antispam)) {
            builder.append_option(text);
        }
        self.entries.push(
            antispam
                .entries()
                .iter()
                .map(|entry| (entry.key.as_ref(), entry.value.as_ref(), entry.offset)),
        );
    }
}

impl ColumnBuilder for MicrosoftAntispamColumn {
    /// Appends the list of every Microsoft antispam header of `mail`, parsed from its raw bytes
    /// in header order; an unparsed message appends an empty list.
    fn append(&mut self, record: &Record<'_>) {
        let mail = record.mail();
        let mut len = 0_usize;
        for (name, value) in mail.into_iter().flat_map(ms_antispam_headers) {
            let (antispam, issues) = parse_ms_antispam(value).into_parts();
            self.header.append_value(name);
            self.push_header(&antispam);
            self.issues.push(issues.iter());
            len = len.saturating_add(1);
        }
        self.shape.push_list(len);
    }

    /// The column, as an Arrow array with one list per message appended.
    ///
    /// # Errors
    ///
    /// The Arrow error when the nested arrays do not fit [`microsoft_antispam_fields`].
    fn finish(&mut self) -> Result<ArrayRef, ArrowError> {
        let mut columns: Vec<ArrayRef> = vec![
            Arc::new(self.header.finish()),
            Arc::new(self.scl.finish()),
            Arc::new(self.bcl.finish()),
            Arc::new(self.client_ip.finish()),
        ];
        columns.extend(
            self.text
                .iter_mut()
                .map(|builder| -> ArrayRef { Arc::new(builder.finish()) }),
        );
        columns.push(self.entries.finish()?);
        columns.push(self.issues.finish()?);
        let values = StructArray::try_new(microsoft_antispam_fields(), columns, None)?;
        self.shape
            .wrap(struct_item(microsoft_antispam_fields()), Arc::new(values))
    }
}

/// The struct of one hop of `received_hops`.
fn hop_fields() -> Fields {
    Fields::from(vec![
        field("header_index", DataType::UInt64),
        field("from_host", DataType::Utf8),
        field("from_comment", DataType::Utf8),
        field("ip", DataType::Utf8),
        field("by_host", DataType::Utf8),
        field("recipient", DataType::Utf8),
        field("id", DataType::Utf8),
        field("protocol", DataType::Utf8),
        field("tls", DataType::Struct(tls_fields())),
        field(
            "date",
            DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
        ),
        field("date_offset_minutes", DataType::Int32),
        field("delay_seconds", DataType::Int64),
        field("first_external", DataType::Boolean),
    ])
}

/// The Arrow type of the `microsoft_antispam` column.
pub(crate) fn microsoft_antispam_type() -> DataType {
    list_of_structs(microsoft_antispam_fields())
}

/// The struct of one `microsoft_antispam` element.
fn microsoft_antispam_fields() -> Fields {
    let mut fields = vec![
        field("header", DataType::Utf8),
        field("scl", DataType::Int8),
        field("bcl", DataType::UInt8),
        field("client_ip", DataType::Utf8),
    ];
    fields.extend(MS_TEXT.iter().map(|name| field(name, DataType::Utf8)));
    fields.push(struct_list_field("entries", pair_fields()));
    with_issues(&Fields::from(fields))
}

/// The Microsoft antispam headers of `mail` in header order, each with its lowercase name and
/// raw value.
fn ms_antispam_headers<'mail>(
    mail: &'mail Mail<'mail>,
) -> impl Iterator<Item = (&'static str, &'mail [u8])> {
    mail.headers().iter().filter_map(|header| {
        let header_name = header.name();
        let name = MS_ANTISPAM_HEADERS
            .iter()
            .find(|known| header_name.as_str().eq_ignore_ascii_case(known))?;
        Some((*name, strip_line_break(header.raw_value())))
    })
}

/// The text entries of `antispam` in the order of [`MS_TEXT`].
fn ms_texts<'antispam>(antispam: &'antispam MsAntispam<'_>) -> [Option<&'antispam str>; 10] {
    [
        antispam.category(),
        antispam.country(),
        antispam.direction(),
        antispam.helo(),
        antispam.ip_verdict(),
        antispam.language(),
        antispam.ptr(),
        antispam.safety(),
        antispam.service(),
        antispam.spam_verdict(),
    ]
}

/// The `{key, value, offset}` struct of one entry or pair.
fn pair_fields() -> Fields {
    Fields::from(vec![
        field("key", DataType::Utf8),
        field("value", DataType::Utf8),
        field("offset", DataType::UInt64),
    ])
}

/// The Arrow type of the `received_hops` column.
pub(crate) fn received_hops_type() -> DataType {
    DataType::Struct(received_hops_fields())
}

/// The struct of one `received_hops` value: the hops plus the issues of the whole chain.
fn received_hops_fields() -> Fields {
    Fields::from(vec![
        struct_list_field("hops", hop_fields()),
        struct_list_field("issues", issue_fields()),
    ])
}

/// The struct of one `received_spf_parsed` element.
fn received_spf_fields() -> Fields {
    with_issues(&Fields::from(vec![
        field("result", DataType::Utf8),
        field("client_ip", DataType::Utf8),
        field("comment", DataType::Utf8),
        struct_list_field("pairs", pair_fields()),
    ]))
}

/// The Arrow type of the `received_spf_parsed` column.
pub(crate) fn received_spf_parsed_type() -> DataType {
    list_of_structs(received_spf_fields())
}

/// The `{version, cipher}` struct of a hop's TLS details.
fn tls_fields() -> Fields {
    Fields::from(vec![
        field("version", DataType::Utf8),
        field("cipher", DataType::Utf8),
    ])
}
