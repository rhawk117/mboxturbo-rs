//! The columns the extraction pipeline offers, and the Arrow type of each.

use std::borrow::Cow;

use arrow_schema::{DataType, Field, TimeUnit};
use mail_parser::{HeaderForm, HeaderName};

use crate::structured;

/// Needs the full MIME parse.
const BODY: u8 = 2;

/// Prefix that selects an arbitrary header column; the rest of the name is the header name.
const HEADER_PREFIX: &str = "header:";

/// Left out of [`Column::defaults`].
const OPT_IN: u8 = 1;

/// Comes from the index or the raw bytes alone.
const UNPARSED: u8 = 4;

/// The row shared by every `header:<Name>` column, which the catalogue does not list.
static HEADER_SPEC: ColumnSpec = ColumnSpec::new("", Column::Header(String::new()), text_list, 0);

/// The catalogue row of every named column; the order is what [`Column::names`] yields.
static NAMED: [ColumnSpec; 33] = [
    ColumnSpec::new("position", Column::Position, uint64, UNPARSED),
    ColumnSpec::new("offset", Column::Offset, uint64, UNPARSED),
    ColumnSpec::new("size", Column::Size, uint64, UNPARSED),
    ColumnSpec::new("raw", Column::Raw, binary, OPT_IN | UNPARSED),
    ColumnSpec::decoded(
        "from",
        Column::From,
        text_list,
        (HeaderName::From, HeaderForm::Addresses),
    ),
    ColumnSpec::decoded(
        "to",
        Column::To,
        text_list,
        (HeaderName::To, HeaderForm::Addresses),
    ),
    ColumnSpec::decoded(
        "cc",
        Column::Cc,
        text_list,
        (HeaderName::Cc, HeaderForm::Addresses),
    ),
    ColumnSpec::decoded(
        "reply_to",
        Column::ReplyTo,
        text_list,
        (HeaderName::ReplyTo, HeaderForm::Addresses),
    ),
    ColumnSpec::decoded(
        "subject",
        Column::Subject,
        utf8,
        (HeaderName::Subject, HeaderForm::Text),
    ),
    ColumnSpec::new("date", Column::Date, utc_micros, UNPARSED),
    ColumnSpec::new(
        "date_offset_minutes",
        Column::DateOffsetMinutes,
        int32,
        UNPARSED,
    ),
    ColumnSpec::decoded(
        "message_id",
        Column::MessageId,
        utf8,
        (HeaderName::MessageId, HeaderForm::MessageIds),
    ),
    ColumnSpec::new("received", Column::Received, text_list, 0),
    ColumnSpec::new(
        "authentication_results",
        Column::AuthenticationResults,
        text_list,
        0,
    ),
    ColumnSpec::new("received_spf", Column::ReceivedSpf, text_list, 0),
    ColumnSpec::new("dkim_signature", Column::DkimSignature, text_list, 0),
    ColumnSpec::new("return_path", Column::ReturnPath, utf8, 0),
    ColumnSpec::new("text", Column::Text, utf8, BODY),
    ColumnSpec::new("html", Column::Html, utf8, BODY),
    ColumnSpec::new("attachment_names", Column::AttachmentNames, text_list, BODY),
    ColumnSpec::new("attachment_types", Column::AttachmentTypes, text_list, BODY),
    ColumnSpec::new("attachment_sizes", Column::AttachmentSizes, size_list, BODY),
    ColumnSpec::new(
        "attachment_sha256",
        Column::AttachmentSha256,
        text_list,
        BODY,
    ),
    ColumnSpec::new(
        "auth_results",
        Column::AuthResults,
        structured::auth_results_type,
        OPT_IN,
    ),
    ColumnSpec::new(
        "arc_sets",
        Column::ArcSets,
        structured::arc_sets_type,
        OPT_IN,
    ),
    ColumnSpec::new(
        "dkim_signatures",
        Column::DkimSignatures,
        structured::dkim_signatures_type,
        OPT_IN,
    ),
    ColumnSpec::new(
        "received_hops",
        Column::ReceivedHops,
        structured::received_hops_type,
        OPT_IN,
    ),
    ColumnSpec::new(
        "received_spf_parsed",
        Column::ReceivedSpfParsed,
        structured::received_spf_parsed_type,
        OPT_IN,
    ),
    ColumnSpec::new(
        "microsoft_antispam",
        Column::MicrosoftAntispam,
        structured::microsoft_antispam_type,
        OPT_IN,
    ),
    ColumnSpec::new("verdict_dmarc", Column::VerdictDmarc, utf8, OPT_IN),
    ColumnSpec::new("verdict_spf", Column::VerdictSpf, utf8, OPT_IN),
    ColumnSpec::new("verdict_dkim", Column::VerdictDkim, utf8, OPT_IN),
    ColumnSpec::new("verdict_compauth", Column::VerdictCompauth, utf8, OPT_IN),
];

/// One catalogue row: everything the pipeline knows about a column besides how it builds its slot.
struct ColumnSpec {
    /// The variant this row describes.
    column: Column,
    /// Builds the Arrow type of the column's values.
    data_type: fn() -> DataType,
    /// The `OPT_IN`, `BODY` and `UNPARSED` traits of the column.
    flags: u8,
    /// The header the column reads and how to decode it, when it reads one decoded.
    header_form: Option<(HeaderName<'static>, HeaderForm)>,
    /// The public name, as accepted by [`Column::from_name`].
    name: &'static str,
}

/// One per-message column the pipeline can extract.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Column {
    /// Every `ARC-Authentication-Results`, `ARC-Message-Signature` and `ARC-Seal` header grouped
    /// into ARC sets by instance, parsed from the raw header bytes; opt-in, never a default.
    ///
    /// One struct per message, never null: `sets: List<Struct>`, one struct per ARC set ordered
    /// by instance and empty when the message has none, and `issues: List<Struct<kind: Utf8,
    /// offset: UInt64>>`, every parse issue of the chain in the parser's order (instance
    /// problems, the cap, tag-list and `ARC-Authentication-Results` problems). A set has
    /// `instance: UInt8`; `seal` and `message_signature`: `List<Struct<name: Utf8, value: Utf8,
    /// offset: UInt64>>`, null when the set lacks that header; `authentication_results`: a
    /// struct with the fields of [`Column::AuthResults`] except `issues`, null when the set
    /// lacks that header; `chain_validation: Utf8`, the seal's `cv` tag, null when absent.
    /// `trusted` inside `authentication_results` is true or false when a trust set was given
    /// to [`Pipeline::with_trust`](crate::Pipeline::with_trust) and null otherwise.
    ArcSets,
    /// Attachment file names; unnamed attachments are null.
    AttachmentNames,
    /// Lowercase hex SHA-256 of each decoded attachment.
    AttachmentSha256,
    /// Decoded attachment sizes in bytes.
    AttachmentSizes,
    /// Attachment media types such as `application/pdf`.
    AttachmentTypes,
    /// Every `Authentication-Results:` header parsed from its raw bytes, in header order;
    /// opt-in, never a default.
    ///
    /// A list of one struct per header, empty when the message has none: `authserv_id: Utf8`;
    /// `version: UInt32`, null when absent; `entries: List<Struct<method: Utf8, result: Utf8,
    /// reason: Utf8 (nullable), properties: List<Struct<ptype: Utf8, property: Utf8, value:
    /// Utf8>>>>`; `trusted: Boolean`, true when the authserv-id is in the trust set given to
    /// [`Pipeline::with_trust`](crate::Pipeline::with_trust), false when it is not and null
    /// when no trust set was given; `issues: List<Struct<kind: Utf8, offset: UInt64>>`, where
    /// `kind` is the `snake_case` name of the issue and `offset` a byte offset into the
    /// header value.
    AuthResults,
    /// Every raw `Authentication-Results:` value.
    AuthenticationResults,
    /// Addresses in `Cc:`.
    Cc,
    /// `Date:` as a UTC timestamp, microsecond precision so Parquet keeps the type.
    Date,
    /// UTC offset of `Date:` in minutes.
    DateOffsetMinutes,
    /// Every raw `DKIM-Signature:` value.
    DkimSignature,
    /// Every `DKIM-Signature:` header parsed from its raw bytes, in header order; opt-in, never
    /// a default.
    ///
    /// A list of one struct per header, empty when the message has none: `version`, `algorithm`,
    /// `body_hash`, `domain`, `selector` and `signature`, each `Utf8` and null when the tag is
    /// absent; `signed_headers: List<Utf8>`; `tags: List<Struct<name: Utf8, value: Utf8,
    /// offset: UInt64>>`, the tags other than those six and `h`; `issues: List<Struct<kind:
    /// Utf8, offset: UInt64>>` as in [`Column::AuthResults`].
    DkimSignatures,
    /// Addresses in `From:`.
    From,
    /// Every raw value of any header, named `header:<Name>`.
    Header(String),
    /// HTML bodies joined by newlines.
    Html,
    /// `Message-ID:` without angle brackets.
    MessageId,
    /// Every `X-Forefront-Antispam-Report:` and `X-Microsoft-Antispam:` header parsed from its
    /// raw bytes, in header order; opt-in, never a default.
    ///
    /// A list of one struct per header, empty when the message has none: `header: Utf8`, the
    /// lowercase header name; `scl: Int8` and `bcl: UInt8`, null when the entry is absent or
    /// not an integer in range; `client_ip: Utf8`, null when `CIP` is not an address;
    /// `category`, `country`, `direction`, `helo`, `ip_verdict`, `language`, `ptr`, `safety`,
    /// `service` and `spam_verdict`, each `Utf8` and null when the entry is absent; `entries:
    /// List<Struct<key: Utf8, value: Utf8, offset: UInt64>>`, every entry as written; `issues:
    /// List<Struct<kind: Utf8, offset: UInt64>>` as in [`Column::AuthResults`]. Offsets are
    /// byte offsets into that header's value.
    MicrosoftAntispam,
    /// Byte offset of the message in the file.
    Offset,
    /// Zero-based position of the message in the mailbox.
    Position,
    /// The message's stored bytes, `From ` separator line included; opt-in, never a default.
    Raw,
    /// Every raw `Received:` value, newest hop first.
    Received,
    /// Every `Received:` header parsed from its raw bytes into one hop chain per message;
    /// opt-in, never a default.
    ///
    /// One struct per message, never null: `hops: List<Struct>`, one struct per `Received`
    /// header and empty when the message has none, oldest hop first, and `issues:
    /// List<Struct<kind: Utf8, offset: UInt64>>`, every parse issue of the chain. An issue's
    /// `offset` is a byte offset into the value of the `Received` header it was found in (the
    /// header is not named, and a cap issue is at 0). A hop has `header_index: UInt64`, the
    /// position of its header among the message's `Received` headers, newest first; `from_host`,
    /// `from_comment`, `ip`, `by_host`, `recipient`, `id` and `protocol`, each `Utf8` and null
    /// when the header lacks the part; `tls: Struct<version: Utf8, cipher: Utf8>`, null when no
    /// TLS details were found and `cipher` null when none is named; `date:
    /// Timestamp(Microsecond, "UTC")` and `date_offset_minutes: Int32`, null when the date is
    /// missing or unreadable; `delay_seconds: Int64` from the previous hop's date, null when
    /// either date is missing; `first_external: Boolean`, true on the first external hop
    /// found with the trust set given to
    /// [`Pipeline::with_trust`](crate::Pipeline::with_trust), false on every other hop and null
    /// when no trust set was given.
    ReceivedHops,
    /// Every raw `Received-SPF:` value.
    ReceivedSpf,
    /// Every `Received-SPF:` header parsed from its raw bytes, in header order; opt-in, never
    /// a default.
    ///
    /// A list of one struct per header, empty when the message has none: `result: Utf8`, the
    /// verdict word, lowercase for the known ones and as written otherwise; `client_ip: Utf8`, null
    /// when the `client-ip` pair is not an address; `comment: Utf8`, null when there is none;
    /// `pairs: List<Struct<key: Utf8, value: Utf8, offset: UInt64>>`, every `key=value` pair in
    /// header order; `issues: List<Struct<kind: Utf8, offset: UInt64>>` as in
    /// [`Column::AuthResults`].
    ReceivedSpfParsed,
    /// Addresses in `Reply-To:`.
    ReplyTo,
    /// First raw `Return-Path:` value.
    ReturnPath,
    /// Length of the message in bytes, separator line included.
    Size,
    /// Decoded `Subject:`.
    Subject,
    /// Plain-text bodies joined by newlines.
    Text,
    /// Addresses in `To:`.
    To,
    /// The `compauth` result word of the newest trusted `Authentication-Results`; opt-in, never a
    /// default. See [`Column::VerdictDmarc`].
    VerdictCompauth,
    /// The `dkim` result word of the newest trusted `Authentication-Results`; opt-in, never a
    /// default. See [`Column::VerdictDmarc`].
    VerdictDkim,
    /// The `dmarc` result word (`pass`, `fail`, `none`, ...) of the first `dmarc` entry in the
    /// topmost trusted `Authentication-Results` that has one; opt-in, never a default.
    ///
    /// Utf8, null when no trust set was given to
    /// [`Pipeline::with_trust`](crate::Pipeline::with_trust) or no trusted header has such an
    /// entry, so a forged header outside the trust set never sets a verdict. Trust is decided as
    /// for the `trusted` flag of [`Column::AuthResults`], including the positional rule of
    /// [`TrustSet::trust_idless_inside`](crate::TrustSet::trust_idless_inside).
    VerdictDmarc,
    /// The `spf` result word of the newest trusted `Authentication-Results`; opt-in, never a
    /// default. See [`Column::VerdictDmarc`].
    VerdictSpf,
}

impl ColumnSpec {
    /// A column that reads `header` decoded as its form.
    const fn decoded(
        name: &'static str,
        column: Column,
        data_type: fn() -> DataType,
        header: (HeaderName<'static>, HeaderForm),
    ) -> Self {
        Self {
            column,
            data_type,
            flags: 0,
            header_form: Some(header),
            name,
        }
    }

    /// Whether the column needs the full MIME parse.
    const fn needs_body(&self) -> bool {
        self.flags & BODY != 0
    }

    /// A column with the traits in `flags` and no decoded header.
    const fn new(
        name: &'static str,
        column: Column,
        data_type: fn() -> DataType,
        flags: u8,
    ) -> Self {
        Self {
            column,
            data_type,
            flags,
            header_form: None,
            name,
        }
    }

    /// Whether the column is left out of the defaults.
    const fn opt_in(&self) -> bool {
        self.flags & OPT_IN != 0
    }

    /// Whether the column needs the message parsed at all.
    const fn parsed(&self) -> bool {
        self.flags & UNPARSED == 0
    }
}

impl Column {
    /// The Arrow type of the values this column extracts; list-typed for multi-valued headers.
    fn data_type(&self) -> DataType {
        (self.spec().data_type)()
    }

    /// The columns selected when none are named: everything that needs only the header block,
    /// except the opt-in [`Column::Raw`] and the structured columns [`Column::AuthResults`],
    /// [`Column::ArcSets`], [`Column::DkimSignatures`], [`Column::ReceivedHops`],
    /// [`Column::ReceivedSpfParsed`] and [`Column::MicrosoftAntispam`].
    #[must_use]
    pub fn defaults() -> Vec<Self> {
        NAMED
            .iter()
            .filter(|spec| !spec.needs_body() && !spec.opt_in())
            .map(|spec| spec.column.clone())
            .collect()
    }

    /// The Arrow field for this column: named by [`Column::name`], always nullable.
    pub(crate) fn field(&self) -> Field {
        Field::new(self.name(), self.data_type(), true)
    }

    /// The column called `name`: one of [`Column::names`], or `header:<Name>` for any header.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        if let Some(header) = name.strip_prefix(HEADER_PREFIX) {
            return (!header.is_empty()).then(|| Self::Header(header.to_owned()));
        }
        NAMED
            .iter()
            .find(|spec| spec.name == name)
            .map(|spec| spec.column.clone())
    }

    /// The header this column reads and how to decode it, or `None` when it needs no header
    /// decoded: it reads the raw bytes, offsets, the body, or a header kept as raw text.
    pub(crate) fn header_form(&self) -> Option<(HeaderName<'static>, HeaderForm)> {
        self.spec().header_form.clone()
    }

    /// Whether this column is left out of [`Column::defaults`]: raw bytes and the structured
    /// header columns.
    #[must_use]
    pub fn is_opt_in(&self) -> bool {
        self.spec().opt_in()
    }

    /// This column's name, as accepted by [`Column::from_name`].
    #[must_use]
    pub fn name(&self) -> Cow<'static, str> {
        if let Self::Header(header) = self {
            return Cow::Owned(format!("{HEADER_PREFIX}{header}"));
        }
        Cow::Borrowed(self.spec().name)
    }

    /// Every named column, in catalogue order.
    pub fn names() -> impl Iterator<Item = &'static str> {
        NAMED.iter().map(|spec| spec.name)
    }

    /// Whether extracting this column needs the full MIME parse rather than the header block.
    #[must_use]
    pub fn needs_body(&self) -> bool {
        self.spec().needs_body()
    }

    /// Whether extracting this column requires parsing the message at all; position, offset,
    /// size, raw bytes and the date columns come from the index or the raw bytes alone.
    pub(crate) fn needs_parsing(&self) -> bool {
        self.spec().parsed()
    }

    /// This column's catalogue row; every header column shares one row.
    #[expect(
        clippy::expect_used,
        reason = "the test `every_non_header_variant_has_its_own_named_row` pins one NAMED row per \
                  non-header variant, so a miss is a catalogue bug, not an input"
    )]
    fn spec(&self) -> &'static ColumnSpec {
        if matches!(self, Self::Header(_)) {
            return &HEADER_SPEC;
        }
        NAMED
            .iter()
            .find(|spec| spec.column == *self)
            .expect("every non-header column has a row in NAMED")
    }
}

/// Raw bytes.
const fn binary() -> DataType {
    DataType::LargeBinary
}

/// A signed 32-bit integer.
const fn int32() -> DataType {
    DataType::Int32
}

/// A list of byte counts.
fn size_list() -> DataType {
    DataType::new_list(DataType::UInt64, true)
}

/// A list of text values.
fn text_list() -> DataType {
    DataType::new_list(DataType::Utf8, true)
}

/// An unsigned 64-bit integer.
const fn uint64() -> DataType {
    DataType::UInt64
}

/// A UTC timestamp, microsecond precision so Parquet keeps the type.
fn utc_micros() -> DataType {
    DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()))
}

/// A text value.
const fn utf8() -> DataType {
    DataType::Utf8
}

#[cfg(test)]
mod tests {
    use super::{Column, NAMED};

    /// Every non-header variant, so a new one without a `NAMED` row fails the test below.
    static NON_HEADER: [Column; 33] = [
        Column::ArcSets,
        Column::AttachmentNames,
        Column::AttachmentSha256,
        Column::AttachmentSizes,
        Column::AttachmentTypes,
        Column::AuthResults,
        Column::AuthenticationResults,
        Column::Cc,
        Column::Date,
        Column::DateOffsetMinutes,
        Column::DkimSignature,
        Column::DkimSignatures,
        Column::From,
        Column::Html,
        Column::MessageId,
        Column::MicrosoftAntispam,
        Column::Offset,
        Column::Position,
        Column::Raw,
        Column::Received,
        Column::ReceivedHops,
        Column::ReceivedSpf,
        Column::ReceivedSpfParsed,
        Column::ReplyTo,
        Column::ReturnPath,
        Column::Size,
        Column::Subject,
        Column::Text,
        Column::To,
        Column::VerdictCompauth,
        Column::VerdictDkim,
        Column::VerdictDmarc,
        Column::VerdictSpf,
    ];

    #[test]
    fn every_non_header_variant_has_its_own_named_row() {
        assert_eq!(
            NAMED.len(),
            NON_HEADER.len(),
            "NAMED has one row for each non-header variant"
        );
        for column in &NON_HEADER {
            assert!(
                NAMED.iter().any(|spec| spec.column == *column),
                "{column:?} has a NAMED row, so spec() never falls back to the header row"
            );
            assert!(
                !matches!(column.spec().column, Column::Header(_)),
                "{column:?} resolves to its own row, not the header row"
            );
        }
    }

    #[test]
    fn every_name_round_trips() {
        for name in Column::names().chain(["header:X-Mailer"]) {
            let column = Column::from_name(name)
                .expect("every catalogued name and a header name parse back to a column");
            assert_eq!(column.name(), name, "name of {column:?}");
        }
    }

    #[test]
    fn unknown_and_empty_header_names_are_rejected() {
        assert_eq!(
            Column::from_name("subjekt"),
            None,
            "a misspelled column name is rejected, not dropped"
        );
        assert_eq!(
            Column::from_name("header:"),
            None,
            "a header: prefix with no header name is rejected"
        );
    }

    #[test]
    fn defaults_never_need_the_body() {
        assert!(
            Column::defaults().iter().all(|column| !column.needs_body()),
            "no default column needs the message body"
        );
        assert!(
            Column::defaults().contains(&Column::Received),
            "the defaults include the Received forensics column"
        );
        assert!(
            !Column::defaults().contains(&Column::Raw),
            "raw is opt-in and not a default"
        );
    }

    #[test]
    fn structured_columns_are_opt_in_and_need_no_body() {
        for name in [
            "auth_results",
            "arc_sets",
            "dkim_signatures",
            "received_hops",
            "received_spf_parsed",
            "microsoft_antispam",
            "verdict_dmarc",
            "verdict_spf",
            "verdict_dkim",
            "verdict_compauth",
        ] {
            let column = Column::from_name(name).expect("a structured column name parses");
            assert!(!column.needs_body(), "{name} reads headers only");
            assert!(column.needs_parsing(), "{name} reads the parsed headers");
            assert!(
                !Column::defaults().contains(&column),
                "{name} is opt-in, not a default"
            );
        }
    }

    #[test]
    fn raw_is_a_catalogued_column_that_needs_no_parsing() {
        assert_eq!(Column::from_name("raw"), Some(Column::Raw), "raw parses");
        assert!(!Column::Raw.needs_body(), "raw needs no body parse");
        assert!(!Column::Raw.needs_parsing(), "raw needs no parse at all");
        for column in [Column::Date, Column::DateOffsetMinutes] {
            assert!(
                !column.needs_parsing(),
                "{column:?} reads the raw bytes only"
            );
        }
    }
}
