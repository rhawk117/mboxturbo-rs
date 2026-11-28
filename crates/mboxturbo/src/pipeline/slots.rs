//! The per-column builders: one typed Arrow builder for each selectable column, and the factory
//! that picks it.

use std::borrow::Cow;
use std::fmt::Debug;
use std::sync::Arc;

use arrow_array::ArrayRef;
use arrow_array::builder::{
    Int32Builder, LargeBinaryBuilder, ListBuilder, StringBuilder, TimestampMicrosecondBuilder,
    UInt64Builder,
};
use arrow_schema::ArrowError;
use mail_parser::AddressList;
use mboxturbo_headers::AuthMethod;
use sha2::{Digest as _, Sha256};

use super::Record;
use crate::columns::Column;
use crate::fields::{self, Mail};
use crate::structured::{
    ArcSetsColumn, AuthResultsColumn, DkimSignaturesColumn, MicrosoftAntispamColumn,
    ReceivedHopsColumn, ReceivedSpfColumn, VerdictColumn,
};
use crate::width::widen;

/// Typed builder for one selected column; each message appends exactly one entry per builder.
pub(crate) trait ColumnBuilder: Debug + Send {
    /// Appends this column's value for `record`; absent or unparsed data becomes null or an empty
    /// list, never an error.
    fn append(&mut self, record: &Record<'_>);

    /// Finishes the builder into an Arrow array and resets it for reuse.
    ///
    /// # Errors
    ///
    /// The Arrow error when a structured column's nested arrays do not fit its layout.
    fn finish(&mut self) -> Result<ArrayRef, ArrowError>;
}

/// Reads a text value of a parsed message: a decoded header or a joined body.
type MailText = for<'any> fn(&'any Mail<'_>) -> Option<Cow<'any, str>>;

/// Reads an unsigned number from the position, span or size of a record.
type RecordNumber = fn(&Record<'_>) -> u64;

/// A column holding one unsigned number per message, taken from where it sits in the mailbox.
#[derive(Debug)]
struct NumberBuilder {
    /// The Arrow builder.
    builder: UInt64Builder,
    /// Reads the number out of a record.
    read: RecordNumber,
}

impl ColumnBuilder for NumberBuilder {
    fn append(&mut self, record: &Record<'_>) {
        self.builder.append_value((self.read)(record));
    }

    fn finish(&mut self) -> Result<ArrayRef, ArrowError> {
        Ok(Arc::new(self.builder.finish()))
    }
}

/// The message's stored bytes, separator line included.
#[derive(Debug)]
struct RawBuilder(LargeBinaryBuilder);

impl ColumnBuilder for RawBuilder {
    fn append(&mut self, record: &Record<'_>) {
        self.0.append_value(record.raw);
    }

    fn finish(&mut self) -> Result<ArrayRef, ArrowError> {
        Ok(Arc::new(self.0.finish()))
    }
}

/// Email addresses of one address header; an absent header gives an empty list.
#[derive(Debug)]
struct AddressesBuilder {
    /// The Arrow builder.
    builder: ListBuilder<StringBuilder>,
    /// The header read.
    header: AddressHeader,
}

impl ColumnBuilder for AddressesBuilder {
    fn append(&mut self, record: &Record<'_>) {
        append_addresses(&mut self.builder, self.header, record.mail);
    }

    fn finish(&mut self) -> Result<ArrayRef, ArrowError> {
        Ok(Arc::new(self.builder.finish()))
    }
}

/// A nullable text column read from the parsed message; null when the message is unparsed or the
/// value is absent.
#[derive(Debug)]
struct TextBuilder {
    /// The Arrow builder.
    builder: StringBuilder,
    /// Reads the value out of the parsed message.
    read: MailText,
}

impl ColumnBuilder for TextBuilder {
    fn append(&mut self, record: &Record<'_>) {
        self.builder
            .append_option(record.mail.and_then(|mail| (self.read)(mail)));
    }

    fn finish(&mut self) -> Result<ArrayRef, ArrowError> {
        Ok(Arc::new(self.builder.finish()))
    }
}

/// Date as UTC microseconds, null when absent or invalid.
#[derive(Debug)]
struct DateBuilder(TimestampMicrosecondBuilder);

impl ColumnBuilder for DateBuilder {
    fn append(&mut self, record: &Record<'_>) {
        self.0
            .append_option(record.date().map(|found| micros(found.unix_seconds)));
    }

    fn finish(&mut self) -> Result<ArrayRef, ArrowError> {
        Ok(Arc::new(self.0.finish()))
    }
}

/// Minutes east of UTC from the Date header, null when absent or invalid.
#[derive(Debug)]
struct DateOffsetBuilder(Int32Builder);

impl ColumnBuilder for DateOffsetBuilder {
    fn append(&mut self, record: &Record<'_>) {
        self.0
            .append_option(record.date().map(|found| found.offset_minutes));
    }

    fn finish(&mut self) -> Result<ArrayRef, ArrowError> {
        Ok(Arc::new(self.0.finish()))
    }
}

/// Every value of the named header (matched in any case); empty list when absent.
#[derive(Debug)]
struct HeaderValuesBuilder {
    /// The Arrow builder.
    builder: ListBuilder<StringBuilder>,
    /// The header name, stored once.
    name: String,
}

impl ColumnBuilder for HeaderValuesBuilder {
    fn append(&mut self, record: &Record<'_>) {
        append_header_values(&mut self.builder, &self.name, record.mail);
    }

    fn finish(&mut self) -> Result<ArrayRef, ArrowError> {
        Ok(Arc::new(self.builder.finish()))
    }
}

/// First value of the named header (matched in any case), null when absent.
#[derive(Debug)]
struct FirstHeaderValueBuilder {
    /// The Arrow builder.
    builder: StringBuilder,
    /// The header name, stored once.
    name: String,
}

impl ColumnBuilder for FirstHeaderValueBuilder {
    fn append(&mut self, record: &Record<'_>) {
        self.builder
            .append_option(first_header_value(&self.name, record.mail));
    }

    fn finish(&mut self) -> Result<ArrayRef, ArrowError> {
        Ok(Arc::new(self.builder.finish()))
    }
}

/// Attachment file names; a nameless attachment is null.
#[derive(Debug)]
struct AttachmentNamesBuilder(ListBuilder<StringBuilder>);

impl ColumnBuilder for AttachmentNamesBuilder {
    fn append(&mut self, record: &Record<'_>) {
        let attachments = record.mail.into_iter().flat_map(fields::attachments);
        self.0
            .values()
            .extend(attachments.map(|attachment| attachment.filename));
        self.0.append(true);
    }

    fn finish(&mut self) -> Result<ArrayRef, ArrowError> {
        Ok(Arc::new(self.0.finish()))
    }
}

/// Attachment content types.
#[derive(Debug)]
struct AttachmentTypesBuilder(ListBuilder<StringBuilder>);

impl ColumnBuilder for AttachmentTypesBuilder {
    fn append(&mut self, record: &Record<'_>) {
        let attachments = record.mail.into_iter().flat_map(fields::attachments);
        self.0
            .values()
            .extend(attachments.map(|attachment| attachment.content_type()));
        self.0.append(true);
    }

    fn finish(&mut self) -> Result<ArrayRef, ArrowError> {
        Ok(Arc::new(self.0.finish()))
    }
}

/// Decoded attachment sizes in bytes.
#[derive(Debug)]
struct AttachmentSizesBuilder(ListBuilder<UInt64Builder>);

impl ColumnBuilder for AttachmentSizesBuilder {
    fn append(&mut self, record: &Record<'_>) {
        let attachments = record.mail.into_iter().flat_map(fields::attachments);
        let sizes = attachments.map(|attachment| Some(widen(attachment.data.len())));
        self.0.values().extend(sizes);
        self.0.append(true);
    }

    fn finish(&mut self) -> Result<ArrayRef, ArrowError> {
        Ok(Arc::new(self.0.finish()))
    }
}

/// Lowercase hex SHA-256 of each decoded attachment.
#[derive(Debug)]
struct AttachmentSha256Builder(ListBuilder<StringBuilder>);

impl ColumnBuilder for AttachmentSha256Builder {
    fn append(&mut self, record: &Record<'_>) {
        let attachments = record.mail.into_iter().flat_map(fields::attachments);
        let digests = attachments.map(|attachment| Some(sha256_hex(&attachment.data)));
        self.0.values().extend(digests);
        self.0.append(true);
    }

    fn finish(&mut self) -> Result<ArrayRef, ArrowError> {
        Ok(Arc::new(self.0.finish()))
    }
}

/// Which address header an address column reads.
#[derive(Debug, Clone, Copy)]
pub(super) enum AddressHeader {
    /// The Cc header.
    Cc,
    /// The From header.
    From,
    /// The Reply-To header.
    ReplyTo,
    /// The To header.
    To,
}

impl AddressHeader {
    /// Reads this header from `mail`, or `None` when the message lacks it.
    pub(super) fn of<'mail>(self, mail: &'mail Mail<'mail>) -> Option<AddressList<'mail>> {
        match self {
            Self::From => mail.from(),
            Self::To => mail.to(),
            Self::Cc => mail.cc(),
            Self::ReplyTo => mail.reply_to(),
        }
    }
}

/// Erases the builder type so every arm of [`column_builder`] returns the same boxed type.
fn boxed(builder: impl ColumnBuilder + 'static) -> Box<dyn ColumnBuilder> {
    Box::new(builder)
}

/// The builder of `column`, preallocating `rows` entries where the builder supports it. The only
/// place that switches on the column.
#[expect(
    clippy::too_many_lines,
    reason = "one arm per column keeps the match exhaustive, so no column is forgotten"
)]
pub(super) fn column_builder(column: &Column, rows: usize) -> Box<dyn ColumnBuilder> {
    let number = |read| {
        boxed(NumberBuilder {
            builder: UInt64Builder::with_capacity(rows),
            read,
        })
    };
    let addresses = |header| {
        boxed(AddressesBuilder {
            builder: text_list(),
            header,
        })
    };
    let text = |read| {
        boxed(TextBuilder {
            builder: StringBuilder::new(),
            read,
        })
    };
    let header_values = |name: &str| {
        boxed(HeaderValuesBuilder {
            builder: text_list(),
            name: name.to_owned(),
        })
    };
    match column {
        Column::Position => number(|record| widen(record.position)),
        Column::Offset => number(|record| widen(record.span.start)),
        Column::Size => number(|record| widen(record.span.len())),
        Column::Raw => boxed(RawBuilder(LargeBinaryBuilder::new())),
        Column::From => addresses(AddressHeader::From),
        Column::To => addresses(AddressHeader::To),
        Column::Cc => addresses(AddressHeader::Cc),
        Column::ReplyTo => addresses(AddressHeader::ReplyTo),
        Column::Subject => text(|mail| mail.subject().map(Cow::Borrowed)),
        Column::Date => boxed(DateBuilder(utc_timestamps(rows))),
        Column::DateOffsetMinutes => boxed(DateOffsetBuilder(Int32Builder::with_capacity(rows))),
        Column::MessageId => text(|mail| mail.message_id().map(Cow::Borrowed)),
        Column::Received => header_values("received"),
        Column::AuthenticationResults => header_values("authentication-results"),
        Column::ReceivedSpf => header_values("received-spf"),
        Column::DkimSignature => header_values("dkim-signature"),
        Column::ReturnPath => boxed(FirstHeaderValueBuilder {
            builder: StringBuilder::new(),
            name: "return-path".to_owned(),
        }),
        Column::Text => text(|mail| Some(Cow::Owned(text_body(mail)))),
        Column::Html => text(|mail| Some(Cow::Owned(html_body(mail)))),
        Column::AttachmentNames => boxed(AttachmentNamesBuilder(text_list())),
        Column::AttachmentTypes => boxed(AttachmentTypesBuilder(text_list())),
        Column::AttachmentSizes => boxed(AttachmentSizesBuilder(ListBuilder::new(
            UInt64Builder::new(),
        ))),
        Column::AttachmentSha256 => boxed(AttachmentSha256Builder(text_list())),
        Column::Header(name) => header_values(name),
        Column::AuthResults => boxed(AuthResultsColumn::new()),
        Column::ArcSets => boxed(ArcSetsColumn::new()),
        Column::DkimSignatures => boxed(DkimSignaturesColumn::new()),
        Column::ReceivedHops => boxed(ReceivedHopsColumn::new()),
        Column::ReceivedSpfParsed => boxed(ReceivedSpfColumn::new()),
        Column::MicrosoftAntispam => boxed(MicrosoftAntispamColumn::new()),
        Column::VerdictDmarc => boxed(VerdictColumn::new(AuthMethod::Dmarc)),
        Column::VerdictSpf => boxed(VerdictColumn::new(AuthMethod::Spf)),
        Column::VerdictDkim => boxed(VerdictColumn::new(AuthMethod::Dkim)),
        Column::VerdictCompauth => boxed(VerdictColumn::new(AuthMethod::CompAuth)),
    }
}

/// Empty builder for a list of nullable strings.
fn text_list() -> ListBuilder<StringBuilder> {
    ListBuilder::new(StringBuilder::new())
}

/// Empty UTC timestamp builder with room for `rows` entries.
fn utc_timestamps(rows: usize) -> TimestampMicrosecondBuilder {
    TimestampMicrosecondBuilder::with_capacity(rows).with_timezone("UTC")
}

/// Appends one list holding the email addresses of `header` in `mail`; an unparsed message or an
/// absent header appends an empty list.
pub(super) fn append_addresses(
    builder: &mut ListBuilder<StringBuilder>,
    header: AddressHeader,
    mail: Option<&Mail<'_>>,
) {
    let addresses = fields::addresses(mail.and_then(|parsed| header.of(parsed)));
    builder
        .values()
        .extend(addresses.map(|address| address.email));
    builder.append(true);
}

/// Appends one list holding every value of the header `name` in `mail`, in order; an unparsed
/// message or an absent header appends an empty list.
pub(super) fn append_header_values(
    builder: &mut ListBuilder<StringBuilder>,
    name: &str,
    mail: Option<&Mail<'_>>,
) {
    let values = mail
        .into_iter()
        .flat_map(|parsed| fields::header_values(parsed, name))
        .map(Some);
    builder.values().extend(values);
    builder.append(true);
}

/// The first value of the header `name` in `mail`, or `None` when unparsed or absent.
pub(super) fn first_header_value<'mail>(
    name: &str,
    mail: Option<&'mail Mail<'mail>>,
) -> Option<Cow<'mail, str>> {
    let parsed = mail?;
    fields::header_values(parsed, name).next()
}

/// The plain-text bodies of `mail` joined by newlines.
pub(super) fn text_body(mail: &Mail<'_>) -> String {
    joined(fields::text_bodies(mail))
}

/// The HTML bodies of `mail` joined by newlines.
pub(super) fn html_body(mail: &Mail<'_>) -> String {
    joined(fields::html_bodies(mail))
}

// `fields::date` only yields years up to 9999 (`parse_date` reads at most four digits), so
// `unix_seconds` stays below 3e11 and the product below 3e17: the saturation is unreachable.
/// Converts Unix seconds to microseconds, saturating at the `i64` bounds.
pub(super) const fn micros(unix_seconds: i64) -> i64 {
    unix_seconds.saturating_mul(1_000_000)
}

/// Joins body parts with `\n`; no parts give an empty string.
pub(super) fn joined<'mail>(bodies: impl Iterator<Item = Cow<'mail, str>>) -> String {
    bodies.collect::<Vec<_>>().join("\n")
}

/// Lowercase hexadecimal SHA-256 digest of `data` (64 characters).
fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .flat_map(|byte| [byte >> 4_u8, byte & 0x0F])
        .filter_map(|nibble| char::from_digit(u32::from(nibble), 16_u32))
        .collect()
}
