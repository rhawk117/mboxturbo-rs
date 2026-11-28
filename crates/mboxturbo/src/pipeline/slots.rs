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
enum AddressHeader {
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
    fn of<'mail>(self, mail: &'mail Mail<'mail>) -> Option<AddressList<'mail>> {
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
fn append_addresses(
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
fn append_header_values(
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
fn first_header_value<'mail>(
    name: &str,
    mail: Option<&'mail Mail<'mail>>,
) -> Option<Cow<'mail, str>> {
    let parsed = mail?;
    fields::header_values(parsed, name).next()
}

/// The plain-text bodies of `mail` joined by newlines.
fn text_body(mail: &Mail<'_>) -> String {
    joined(fields::text_bodies(mail))
}

/// The HTML bodies of `mail` joined by newlines.
fn html_body(mail: &Mail<'_>) -> String {
    joined(fields::html_bodies(mail))
}

// `fields::date` only yields years up to 9999 (`parse_date` reads at most four digits), so
// `unix_seconds` stays below 3e11 and the product below 3e17: the saturation is unreachable.
/// Converts Unix seconds to microseconds, saturating at the `i64` bounds.
const fn micros(unix_seconds: i64) -> i64 {
    unix_seconds.saturating_mul(1_000_000)
}

/// Joins body parts with `\n`; no parts give an empty string.
fn joined<'mail>(bodies: impl Iterator<Item = Cow<'mail, str>>) -> String {
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

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::cell::OnceCell;
    use std::iter;
    use std::sync::Arc;

    use arrow_array::builder::{ListBuilder, StringBuilder};
    use arrow_array::cast::AsArray as _;
    use arrow_array::types::{TimestampMicrosecondType, UInt64Type};
    use arrow_array::{Array as _, ArrayRef, ListArray};
    use arrow_schema::{DataType, Field, TimeUnit};
    use mail_parser::MessageParser;

    use super::{
        AddressHeader, append_addresses, append_header_values, column_builder, first_header_value,
        html_body, joined, micros, text_body,
    };
    use crate::columns::Column;
    use crate::fields;
    use crate::fields::Mail;
    use crate::pipeline::Record;

    const MULTIPART: &[u8] = b"From: a@example.org\r\nTo: b@example.org, c@example.org\r\n\
Cc: d@example.org\r\nReply-To: e@example.org\r\nReceived: first\r\nReceived: second\r\n\
Date: Thu, 01 Jan 1970 00:00:10 +0130\r\n\
Content-Type: multipart/alternative; boundary=\"b\"\r\n\r\n\
--b\r\nContent-Type: text/plain\r\n\r\nplain part\r\n--b\r\nContent-Type: text/html\r\n\r\n\
<p>html part</p>\r\n--b--\r\n";

    const HEADERS: &[u8] = b"DKIM-Signature: sig\r\nReturn-Path: <one@example.org>\r\n\
Return-Path: <two@example.org>\r\nReceived: first\r\nReceived: second\r\nX-A: a\r\n\r\nbody\r\n";

    const ATTACHED: &[u8] = b"Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n\
--b\r\nContent-Type: text/plain\r\n\r\nbody\r\n--b\r\n\
Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=a.bin\r\n\r\n\
12345\r\n--b--\r\n";

    fn parse(raw: &[u8]) -> Mail<'_> {
        MessageParser::new()
            .parse(raw)
            .expect("fixture message parses")
    }

    fn list_cells(array: &ListArray, row: usize) -> Vec<String> {
        array
            .value(row)
            .as_string::<i32>()
            .iter()
            .map(|cell| cell.expect("fixture cells are non-null").to_owned())
            .collect()
    }

    fn address_cells(header: AddressHeader, mail: Option<&Mail<'_>>) -> Vec<String> {
        let mut builder = ListBuilder::new(StringBuilder::new());
        append_addresses(&mut builder, header, mail);
        list_cells(&builder.finish(), 0)
    }

    #[test]
    fn each_address_header_reads_its_own_header() {
        let mail = parse(MULTIPART);
        let read = |header| address_cells(header, Some(&mail));
        assert_eq!(
            read(AddressHeader::From),
            ["a@example.org"],
            "From reads only the From header's address"
        );
        assert_eq!(
            read(AddressHeader::To),
            ["b@example.org", "c@example.org"],
            "To keeps every address"
        );
        assert_eq!(
            read(AddressHeader::Cc),
            ["d@example.org"],
            "Cc reads the Cc header, not Reply-To"
        );
        assert_eq!(
            read(AddressHeader::ReplyTo),
            ["e@example.org"],
            "Reply-To reads the Reply-To header, not Cc"
        );
    }

    #[test]
    fn an_unparsed_message_appends_an_empty_address_list() {
        assert!(
            address_cells(AddressHeader::From, None).is_empty(),
            "no mail gives an empty list"
        );
    }

    #[test]
    fn repeated_headers_append_all_values_in_order() {
        let mail = parse(MULTIPART);
        let mut builder = ListBuilder::new(StringBuilder::new());
        append_header_values(&mut builder, "received", Some(&mail));
        append_header_values(&mut builder, "x-missing", Some(&mail));
        let array = builder.finish();
        assert_eq!(
            list_cells(&array, 0),
            ["first", "second"],
            "both values, in order"
        );
        assert_eq!(array.len(), 2, "each call appends exactly one list");
        assert!(
            list_cells(&array, 1).is_empty(),
            "an absent header gives an empty list"
        );
    }

    #[test]
    fn the_first_header_value_wins_and_absence_is_none() {
        let mail = parse(MULTIPART);
        assert_eq!(
            first_header_value("received", Some(&mail)).as_deref(),
            Some("first"),
            "first of the repeated values"
        );
        assert_eq!(
            first_header_value("x-missing", Some(&mail)),
            None,
            "an absent header has no first value"
        );
        assert_eq!(
            first_header_value("received", None),
            None,
            "unparsed message"
        );
    }

    #[test]
    fn the_date_header_gives_utc_microseconds_and_a_minute_offset() {
        assert_eq!(
            fields::date(MULTIPART).map(|found| micros(found.unix_seconds)),
            Some(-5_390_000_000),
            "00:00:10 at +01:30 is 5390 seconds before the epoch"
        );
        assert_eq!(
            fields::date(MULTIPART).map(|found| found.offset_minutes),
            Some(90_i32),
            "+0130 is 90 minutes east"
        );
    }

    #[test]
    fn an_empty_message_has_no_date() {
        assert_eq!(
            fields::date(b"").map(|found| micros(found.unix_seconds)),
            None,
            "no micros without a message"
        );
        assert_eq!(
            fields::date(b"").map(|found| found.offset_minutes),
            None,
            "no offset without a message"
        );
    }

    #[test]
    fn text_and_html_bodies_are_not_swapped() {
        let mail = parse(MULTIPART);
        assert_eq!(text_body(&mail), "plain part", "text/plain part");
        assert_eq!(html_body(&mail), "<p>html part</p>", "text/html part");
    }

    #[test]
    fn body_parts_are_joined_by_newlines_and_none_gives_empty() {
        let parts = [Cow::Borrowed("a"), Cow::Borrowed("b")];
        assert_eq!(
            joined(parts.into_iter()),
            "a\nb",
            "newline between parts only"
        );
        assert_eq!(joined(iter::empty()), "", "no parts give an empty string");
    }

    /// Builds `column`, appends the one message `raw` (parsed) and finishes it.
    fn built(column: &Column, raw: &[u8]) -> ArrayRef {
        let mail = parse(raw);
        let record = Record {
            date: OnceCell::new(),
            mail: Some(&mail),
            position: 0,
            raw,
            span: 0..raw.len(),
            trust: None,
        };
        let mut builder = column_builder(column, 1);
        builder.append(&record);
        builder.finish().expect("fixture column finishes")
    }

    #[test]
    fn date_slots_are_built_in_utc() {
        let array = built(&Column::Date, MULTIPART);
        assert_eq!(
            array.data_type(),
            &DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            "timestamps carry the UTC zone"
        );
        assert_eq!(
            array.as_primitive::<TimestampMicrosecondType>().value(0),
            -5_390_000_000,
            "the built date column holds the UTC microseconds of the Date header"
        );
    }

    #[test]
    fn header_columns_read_each_value_from_the_header_they_name() {
        let list = |column| list_cells(built(&column, HEADERS).as_list::<i32>(), 0);
        assert_eq!(
            list(Column::DkimSignature),
            ["sig"],
            "DKIM-Signature is read from its mixed-case header"
        );
        assert_eq!(
            list(Column::Header("x-a".to_owned())),
            ["a"],
            "a custom header is read under the name the caller gave"
        );
        assert_eq!(
            built(&Column::ReturnPath, HEADERS)
                .as_string::<i32>()
                .iter()
                .collect::<Vec<_>>(),
            [Some("<one@example.org>")],
            "Return-Path is read from its header as one string"
        );
    }

    #[test]
    fn return_path_keeps_only_the_first_value_while_received_keeps_all() {
        let return_path = built(&Column::ReturnPath, HEADERS);
        assert_eq!(
            return_path.data_type(),
            &DataType::Utf8,
            "return-path is a single-value column"
        );
        assert_eq!(
            return_path.as_string::<i32>().value(0),
            "<one@example.org>",
            "the second Return-Path is dropped"
        );
        assert_eq!(
            list_cells(built(&Column::Received, HEADERS).as_list::<i32>(), 0),
            ["first", "second"],
            "received is a list holding every value"
        );
    }

    #[test]
    fn the_attachment_sizes_column_gets_a_size_list_slot() {
        let array = built(&Column::AttachmentSizes, ATTACHED);
        assert_eq!(
            array.data_type(),
            &DataType::List(Arc::new(Field::new_list_field(DataType::UInt64, true))),
            "sizes are numeric lists"
        );
        let sizes = array.as_list::<i32>().value(0);
        assert_eq!(
            sizes.as_primitive::<UInt64Type>().values().to_vec(),
            [5_u64],
            "the attachment holds five decoded bytes"
        );
    }
}
