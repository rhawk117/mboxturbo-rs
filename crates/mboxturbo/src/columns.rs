//! The columns the extraction pipeline offers, and the Arrow type of each.

use std::borrow::Cow;

use arrow_schema::{DataType, Field, TimeUnit};

/// One per-message column the pipeline can extract.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Column {
    /// Zero-based position of the message in the mailbox.
    Position,
    /// Byte offset of the message in the file.
    Offset,
    /// Length of the message in bytes, separator line included.
    Size,
    /// Addresses in `From:`.
    From,
    /// Addresses in `To:`.
    To,
    /// Addresses in `Cc:`.
    Cc,
    /// Addresses in `Reply-To:`.
    ReplyTo,
    /// Decoded `Subject:`.
    Subject,
    /// `Date:` as a UTC timestamp, microsecond precision so Parquet keeps the type.
    Date,
    /// UTC offset of `Date:` in minutes.
    DateOffsetMinutes,
    /// `Message-ID:` without angle brackets.
    MessageId,
    /// Every raw `Received:` value, newest hop first.
    Received,
    /// Every raw `Authentication-Results:` value.
    AuthenticationResults,
    /// Every raw `Received-SPF:` value.
    ReceivedSpf,
    /// Every raw `DKIM-Signature:` value.
    DkimSignature,
    /// First raw `Return-Path:` value.
    ReturnPath,
    /// Plain-text bodies joined by newlines.
    Text,
    /// HTML bodies joined by newlines.
    Html,
    /// Attachment file names; unnamed attachments are null.
    AttachmentNames,
    /// Attachment media types such as `application/pdf`.
    AttachmentTypes,
    /// Decoded attachment sizes in bytes.
    AttachmentSizes,
    /// Lowercase hex SHA-256 of each decoded attachment.
    AttachmentSha256,
    /// Every raw value of any header, named `header:<Name>`.
    Header(String),
}

/// Prefix that selects an arbitrary header column; the rest of the name is the header name.
const HEADER_PREFIX: &str = "header:";

/// Public name and variant of every named column; the order is what [`Column::names`] yields.
const NAMED: [(&str, Column); 22] = [
    ("position", Column::Position),
    ("offset", Column::Offset),
    ("size", Column::Size),
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
];

impl Column {
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

    /// Every named column, in catalogue order.
    pub fn names() -> impl Iterator<Item = &'static str> {
        NAMED.iter().map(|(name, _)| *name)
    }

    /// The columns selected when none are named: everything that needs only the header block.
    #[must_use]
    pub fn defaults() -> Vec<Self> {
        NAMED
            .iter()
            .map(|(_, column)| column.clone())
            .filter(|column| !column.needs_body())
            .collect()
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

    /// Whether extracting this column requires parsing the message at all; position, offset and
    /// size come from the index alone.
    pub(crate) const fn needs_parsing(&self) -> bool {
        !matches!(self, Self::Position | Self::Offset | Self::Size)
    }

    /// The Arrow field for this column: named by [`Column::name`], always nullable.
    pub(crate) fn field(&self) -> Field {
        Field::new(self.name(), self.data_type(), true)
    }

    /// The Arrow type of the values this column extracts; list-typed for multi-valued headers.
    fn data_type(&self) -> DataType {
        let text_list = DataType::new_list(DataType::Utf8, true);
        match self {
            Self::Position | Self::Offset | Self::Size => DataType::UInt64,
            Self::Subject | Self::MessageId | Self::ReturnPath | Self::Text | Self::Html => {
                DataType::Utf8
            },
            Self::Date => DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            Self::DateOffsetMinutes => DataType::Int32,
            Self::AttachmentSizes => DataType::new_list(DataType::UInt64, true),
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
            "headers only"
        );
        assert!(
            Column::defaults().contains(&Column::Received),
            "forensics headers included"
        );
    }
}
