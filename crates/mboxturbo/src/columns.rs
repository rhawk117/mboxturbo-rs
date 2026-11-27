//! The columns the extraction pipeline offers, and the Arrow type of each.

use std::borrow::Cow;

use arrow_schema::{DataType, Field, TimeUnit};

use crate::structured;

/// Prefix that selects an arbitrary header column; the rest of the name is the header name.
const HEADER_PREFIX: &str = "header:";

/// Public name and variant of every named column; the order is what [`Column::names`] yields.
const NAMED: [(&str, Column); 33] = [
    ("position", Column::Position),
    ("offset", Column::Offset),
    ("size", Column::Size),
    ("raw", Column::Raw),
    ("from", Column::From),
    ("to", Column::To),
    ("cc", Column::Cc),
    ("reply_to", Column::ReplyTo),
    ("subject", Column::Subject),
    ("date", Column::Date),
    ("date_offset_minutes", Column::DateOffsetMinutes),
    ("message_id", Column::MessageId),
    ("received", Column::Received),
    ("authentication_results", Column::AuthenticationResults),
    ("received_spf", Column::ReceivedSpf),
    ("dkim_signature", Column::DkimSignature),
    ("return_path", Column::ReturnPath),
    ("text", Column::Text),
    ("html", Column::Html),
    ("attachment_names", Column::AttachmentNames),
    ("attachment_types", Column::AttachmentTypes),
    ("attachment_sizes", Column::AttachmentSizes),
    ("attachment_sha256", Column::AttachmentSha256),
    ("auth_results", Column::AuthResults),
    ("arc_sets", Column::ArcSets),
    ("dkim_signatures", Column::DkimSignatures),
    ("received_hops", Column::ReceivedHops),
    ("received_spf_parsed", Column::ReceivedSpfParsed),
    ("microsoft_antispam", Column::MicrosoftAntispam),
    ("verdict_dmarc", Column::VerdictDmarc),
    ("verdict_spf", Column::VerdictSpf),
    ("verdict_dkim", Column::VerdictDkim),
    ("verdict_compauth", Column::VerdictCompauth),
];

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

impl Column {
    /// The Arrow type of the values this column extracts; list-typed for multi-valued headers.
    #[expect(
        clippy::too_many_lines,
        reason = "one arm per column keeps the match exhaustive, so no column is forgotten"
    )]
    fn data_type(&self) -> DataType {
        let text_list = DataType::new_list(DataType::Utf8, true);
        match self {
            Self::Position | Self::Offset | Self::Size => DataType::UInt64,
            Self::Subject
            | Self::MessageId
            | Self::ReturnPath
            | Self::Text
            | Self::Html
            | Self::VerdictDmarc
            | Self::VerdictSpf
            | Self::VerdictDkim
            | Self::VerdictCompauth => DataType::Utf8,
            Self::Date => DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            Self::DateOffsetMinutes => DataType::Int32,
            Self::Raw => DataType::LargeBinary,
            Self::AttachmentSizes => DataType::new_list(DataType::UInt64, true),
            Self::AuthResults => structured::auth_results_type(),
            Self::ArcSets => structured::arc_sets_type(),
            Self::DkimSignatures => structured::dkim_signatures_type(),
            Self::ReceivedHops => structured::received_hops_type(),
            Self::ReceivedSpfParsed => structured::received_spf_parsed_type(),
            Self::MicrosoftAntispam => structured::microsoft_antispam_type(),
            Self::From
            | Self::To
            | Self::Cc
            | Self::ReplyTo
            | Self::Received
            | Self::AuthenticationResults
            | Self::ReceivedSpf
            | Self::DkimSignature
            | Self::AttachmentNames
            | Self::AttachmentTypes
            | Self::AttachmentSha256
            | Self::Header(_) => text_list,
        }
    }

    /// The columns selected when none are named: everything that needs only the header block,
    /// except the opt-in [`Column::Raw`] and the structured columns [`Column::AuthResults`],
    /// [`Column::ArcSets`], [`Column::DkimSignatures`], [`Column::ReceivedHops`],
    /// [`Column::ReceivedSpfParsed`] and [`Column::MicrosoftAntispam`].
    #[must_use]
    pub fn defaults() -> Vec<Self> {
        NAMED
            .iter()
            .map(|(_, column)| column.clone())
            .filter(|column| !column.needs_body() && !column.is_opt_in())
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
            .find(|(known, _)| *known == name)
            .map(|(_, column)| column.clone())
    }

    /// Whether this column is left out of [`Column::defaults`]: raw bytes and the structured
    /// header columns.
    const fn is_opt_in(&self) -> bool {
        matches!(
            self,
            Self::Raw
                | Self::AuthResults
                | Self::ArcSets
                | Self::DkimSignatures
                | Self::ReceivedHops
                | Self::ReceivedSpfParsed
                | Self::MicrosoftAntispam
                | Self::VerdictDmarc
                | Self::VerdictSpf
                | Self::VerdictDkim
                | Self::VerdictCompauth
        )
    }

    /// This column's name, as accepted by [`Column::from_name`].
    #[must_use]
    pub fn name(&self) -> Cow<'static, str> {
        if let Self::Header(header) = self {
            return Cow::Owned(format!("{HEADER_PREFIX}{header}"));
        }
        NAMED
            .iter()
            .find(|(_, column)| column == self)
            .map_or(Cow::Borrowed(""), |(name, _)| Cow::Borrowed(*name))
    }

    /// Every named column, in catalogue order.
    pub fn names() -> impl Iterator<Item = &'static str> {
        NAMED.iter().map(|(name, _)| *name)
    }

    /// Whether extracting this column needs the full MIME parse rather than the header block.
    #[must_use]
    pub const fn needs_body(&self) -> bool {
        matches!(
            self,
            Self::Text
                | Self::Html
                | Self::AttachmentNames
                | Self::AttachmentTypes
                | Self::AttachmentSizes
                | Self::AttachmentSha256
        )
    }

    /// Whether extracting this column requires parsing the message at all; position, offset,
    /// size, raw bytes and the date columns come from the index or the raw bytes alone.
    pub(crate) const fn needs_parsing(&self) -> bool {
        !matches!(
            self,
            Self::Position
                | Self::Offset
                | Self::Size
                | Self::Raw
                | Self::Date
                | Self::DateOffsetMinutes
        )
    }
}

#[cfg(test)]
mod tests {
    use super::Column;

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
