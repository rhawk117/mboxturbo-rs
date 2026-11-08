//! Columnar extraction: parse only what the selected columns need, in parallel, into Arrow
//! record batches, and stream them to a consumer or a Parquet file.

use std::borrow::Cow;
use std::collections::VecDeque;
use std::fs::File;
use std::ops::Range;
use std::panic::resume_unwind;
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::{SyncSender, sync_channel};
use std::{iter, thread};

use arrow_array::builder::{
    Int32Builder, ListBuilder, StringBuilder, TimestampMicrosecondBuilder, UInt64Builder,
};
use arrow_array::{ArrayRef, RecordBatch, RecordBatchReader};
use arrow_schema::{ArrowError, Schema, SchemaRef};
use mail_parser::{AddressList, HeaderForm, HeaderName, MessageParser};
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression as ParquetCompression, ZstdLevel};
use parquet::errors::ParquetError;
use parquet::file::properties::{EnabledStatistics, WriterProperties};
use rayon::prelude::*;
use sha2::{Digest as _, Sha256};
use tempfile::NamedTempFile;

use crate::columns::Column;
use crate::error::MboxturboError;
use crate::fields::{
    self, Mail, builtin_table_with_raw_received, contain_parser_panic, strip_separator,
};
use crate::mailbox::Mailbox;
use crate::width::widen;

/// Parquet page compression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Compression {
    /// Snappy: cheaper to decode than Zstd, at the cost of larger files.
    Snappy,
    /// No compression.
    Uncompressed,
    /// Zstandard at level 1: a good ratio at close to Snappy speed.
    #[default]
    Zstd,
}

/// How much of each message must be parsed to fill the selected columns; the cheapest depth that
/// covers them is chosen so unused parsing work is skipped.
#[derive(Debug)]
enum Depth {
    /// Only the headers the selected columns read are parsed; the rest of the message is skipped.
    Headers(MessageParser),
    /// Columns need only raw bytes and offsets, so no message is parsed.
    Nothing,
    /// The body is parsed too, because a body or attachment column is selected.
    Whole(MessageParser),
}

/// A reusable extraction plan: which columns, how deep to parse, and how many rows per batch.
#[derive(Debug)]
pub struct Pipeline {
    /// Rows per batch; never zero.
    batch_size: usize,
    /// Selected columns, in output order.
    columns: Box<[Column]>,
    /// Parse depth required by `columns`.
    depth: Depth,
    /// Arrow schema derived from `columns`, shared by every batch.
    schema: SchemaRef,
}

/// One message as seen by the column builders: where it sits in the mailbox and its parsed form.
struct Record<'mail> {
    /// Parsed message, or `None` when no column needs parsing or the parser rejected or panicked
    /// on it.
    mail: Option<&'mail Mail<'mail>>,
    /// Zero-based index of the message in the mailbox.
    position: usize,
    /// Byte range of the message in the mailbox file.
    span: Range<usize>,
}

/// Batches over a whole mailbox, produced a window at a time on all rayon threads.
#[derive(Debug)]
pub struct BatchReader {
    /// Mailbox being read.
    mailbox: Arc<Mailbox>,
    /// Position of the first message not yet scheduled for extraction.
    next: usize,
    /// Plan that decides columns, schema and batch size.
    pipeline: Arc<Pipeline>,
    /// Extracted batches, in mailbox order, awaiting delivery.
    ready: VecDeque<Result<RecordBatch, MboxturboError>>,
}

impl Pipeline {
    /// Drains a batch reader on a producer thread into `writer` and closes it, returning the
    /// number of rows written.
    ///
    /// # Errors
    ///
    /// [`MboxturboError::Parquet`] if writing or closing fails, or the first batch error
    /// ([`MboxturboError::Arrow`]) the reader yields; extraction stops at that error.
    ///
    /// # Panics
    ///
    /// Re-raises a panic from the producer thread on the calling thread.
    fn encode_parquet(
        self: &Arc<Self>,
        mailbox: &Arc<Mailbox>,
        mut writer: ArrowWriter<File>,
        path: &Path,
    ) -> Result<u64, MboxturboError> {
        let parquet_error = |source| parquet_failure(path, source);
        let (sender, receiver) = sync_channel(rayon::current_num_threads().saturating_mul(2));
        let mut batches = self.reader(mailbox);
        let reader = iter::from_fn(move || batches.next_batch());
        let produced = thread::scope(|scope| {
            let reader_thread = scope.spawn(move || forward_batches(reader, &sender));
            let rows = receiver.into_iter().try_fold(0_u64, |rows, received| {
                let batch = received?;
                writer.write(&batch).map_err(parquet_error)?;
                Ok::<u64, MboxturboError>(rows.saturating_add(widen(batch.num_rows())))
            });
            if let Err(payload) = reader_thread.join() {
                resume_unwind(payload);
            }
            rows
        })?;
        writer.close().map(|_metadata| ()).map_err(parquet_error)?;
        Ok(produced)
    }

    /// Extracts the messages at `positions` (clamped to those that exist) into one batch.
    ///
    /// # Errors
    ///
    /// [`MboxturboError::Arrow`], naming the clamped positions, if the columns cannot be
    /// assembled into a batch.
    pub fn extract(
        &self,
        mailbox: &Mailbox,
        positions: Range<usize>,
    ) -> Result<RecordBatch, MboxturboError> {
        let clamped = clamp_positions(positions, mailbox.len());
        let mut slots: Vec<Slot> = self
            .columns
            .iter()
            .map(|column| Slot::new(column, clamped.len()))
            .collect();
        for (position, span, raw) in mailbox.rows(clamped.clone()) {
            let parsed = self.parse(raw);
            let record = Record {
                position,
                span,
                mail: parsed.as_ref(),
            };
            for slot in &mut slots {
                slot.append(&record);
            }
        }
        let arrays: Vec<ArrayRef> = slots.iter_mut().map(Slot::finish).collect();
        RecordBatch::try_new(self.schema(), arrays).map_err(|source| MboxturboError::Arrow {
            positions: clamped,
            source,
        })
    }

    /// Plans extraction of `columns` in batches of `batch_size` rows (at least one).
    #[must_use]
    pub fn new(columns: Vec<Column>, batch_size: usize) -> Self {
        let fields: Vec<_> = columns.iter().map(Column::field).collect();
        Self {
            depth: depth_for(&columns),
            schema: Arc::new(Schema::new(fields)),
            columns: columns.into_boxed_slice(),
            batch_size: batch_size.max(1),
        }
    }

    /// Parses `raw` just deeply enough for the selected columns, after stripping the mbox separator
    /// line. Returns `None` when no column needs parsing, or when the parser fails or panics on
    /// this message.
    fn parse<'raw>(&self, raw: &'raw [u8]) -> Option<Mail<'raw>> {
        let message = strip_separator(raw);
        match &self.depth {
            Depth::Nothing => None,
            Depth::Headers(parser) => contain_parser_panic(|| parser.parse_headers(message)),
            Depth::Whole(parser) => contain_parser_panic(|| parser.parse(message)),
        }
    }

    /// Streams batches over the whole mailbox, extracting several batches in parallel at a time.
    #[must_use]
    pub fn reader(self: &Arc<Self>, mailbox: &Arc<Mailbox>) -> BatchReader {
        BatchReader {
            pipeline: Arc::clone(self),
            mailbox: Arc::clone(mailbox),
            next: 0,
            ready: VecDeque::new(),
        }
    }

    /// The Arrow schema of every batch this pipeline produces.
    #[must_use]
    pub fn schema(&self) -> SchemaRef {
        Arc::clone(&self.schema)
    }

    /// Splits the span of messages from `from` onward that all threads can work on at once (two
    /// batches per thread) into batch-sized position ranges. Empty when `from` is at or past
    /// the end of `mailbox`; the last range may be shorter than the batch size.
    fn window(&self, from: usize, mailbox: &Mailbox) -> Vec<Range<usize>> {
        let span = self
            .batch_size
            .saturating_mul(rayon::current_num_threads().saturating_mul(2));
        let end = from.saturating_add(span).min(mailbox.len());
        (from..end)
            .step_by(self.batch_size)
            .map(|start| start..start.saturating_add(self.batch_size).min(end))
            .collect()
    }

    /// Writes every batch to a Parquet file at `path`, atomically, while the next batches are
    /// extracted on other threads. Returns the number of rows written.
    ///
    /// # Errors
    ///
    /// [`MboxturboError::Io`] when the file cannot be created or renamed into place,
    /// [`MboxturboError::Parquet`] when encoding fails, and [`MboxturboError::Arrow`] if a
    /// batch cannot be assembled.
    pub fn write_parquet(
        self: &Arc<Self>,
        mailbox: &Arc<Mailbox>,
        path: &Path,
        compression: Compression,
    ) -> Result<u64, MboxturboError> {
        let directory = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty());
        let staged = NamedTempFile::new_in(directory.unwrap_or_else(|| Path::new(".")))
            .map_err(|source| MboxturboError::io(path, source))?;
        let file = staged
            .reopen()
            .map_err(|source| MboxturboError::io(path, source))?;
        let properties = WriterProperties::builder()
            .set_compression(parquet_compression(compression))
            .set_max_row_group_row_count(Some(self.batch_size.saturating_mul(16)))
            .set_dictionary_enabled(false)
            .set_statistics_enabled(EnabledStatistics::Chunk)
            .build();
        let writer = ArrowWriter::try_new(file, self.schema(), Some(properties))
            .map_err(|source| parquet_failure(path, source))?;
        let rows = self.encode_parquet(mailbox, writer, path)?;
        staged
            .persist(path)
            .map(|_persisted| ())
            .map_err(|failure| MboxturboError::io(path, failure.error))?;
        Ok(rows)
    }
}

impl BatchReader {
    /// The next batch, keeping the typed error so callers can read the positions it covers.
    fn next_batch(&mut self) -> Option<Result<RecordBatch, MboxturboError>> {
        if self.ready.is_empty() {
            let window = self.pipeline.window(self.next, &self.mailbox);
            self.next = window.last().map_or(self.next, |last| last.end);
            self.mailbox
                .prefetch(self.next..self.next.saturating_add(self.pipeline.batch_size));
            let extracted: Vec<_> = window
                .into_par_iter()
                .map(|positions| self.pipeline.extract(&self.mailbox, positions))
                .collect();
            self.ready.extend(extracted);
        }
        self.ready.pop_front()
    }
}

impl Iterator for BatchReader {
    type Item = Result<RecordBatch, ArrowError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_batch()
            .map(|batch| batch.map_err(|error| ArrowError::ExternalError(Box::new(error))))
    }
}

impl RecordBatchReader for BatchReader {
    fn schema(&self) -> SchemaRef {
        self.pipeline.schema()
    }
}

#[derive(Debug)]
/// Typed column builder for one selected column; each message appends exactly one entry per slot.
enum Slot {
    /// Email addresses of one address header; an absent header gives an empty list.
    Addresses(AddressHeader, ListBuilder<StringBuilder>),
    /// One of the attachment list columns.
    Attachments(AttachmentSlot),
    /// Date as UTC microseconds, null when absent or invalid.
    Date(TimestampMicrosecondBuilder),
    /// Minutes east of UTC from the Date header, null when absent or invalid.
    DateOffset(Int32Builder),
    /// First value of the named header (lowercase name), null when absent.
    FirstHeaderValue(String, StringBuilder),
    /// Every value of the named header (lowercase name); empty list when absent.
    HeaderValues(String, ListBuilder<StringBuilder>),
    /// HTML bodies joined by newlines, null when the message is unparsed.
    Html(StringBuilder),
    /// First Message-ID, null when absent.
    MessageId(StringBuilder),
    /// Byte offset of the message start.
    Offset(UInt64Builder),
    /// Message index.
    Position(UInt64Builder),
    /// Message length in bytes.
    Size(UInt64Builder),
    /// Decoded subject, null when absent.
    Subject(StringBuilder),
    /// Plain-text bodies joined by newlines, null when the message is unparsed.
    Text(StringBuilder),
}

#[derive(Debug)]
/// Builder for one per-attachment list column; each message contributes one list, which is
/// empty when it has no attachments.
enum AttachmentSlot {
    /// Attachment file names; a nameless attachment is null.
    Names(ListBuilder<StringBuilder>),
    /// Lowercase hex SHA-256 of each decoded attachment.
    Sha256(ListBuilder<StringBuilder>),
    /// Decoded attachment sizes in bytes.
    Sizes(ListBuilder<UInt64Builder>),
    /// Attachment content types.
    Types(ListBuilder<StringBuilder>),
}

impl AttachmentSlot {
    /// Appends this message's attachment list; an unparsed message (`None`) appends an empty list.
    fn append(&mut self, mail: Option<&Mail<'_>>) {
        let attachments = mail.into_iter().flat_map(fields::attachments);
        match self {
            Self::Names(builder) => {
                builder
                    .values()
                    .extend(attachments.map(|attachment| attachment.filename));
                builder.append(true);
            },
            Self::Types(builder) => {
                builder
                    .values()
                    .extend(attachments.map(|attachment| attachment.content_type()));
                builder.append(true);
            },
            Self::Sizes(builder) => {
                let sizes = attachments.map(|attachment| Some(widen(attachment.data.len())));
                builder.values().extend(sizes);
                builder.append(true);
            },
            Self::Sha256(builder) => {
                let digests = attachments.map(|attachment| Some(sha256_hex(&attachment.data)));
                builder.values().extend(digests);
                builder.append(true);
            },
        }
    }

    /// Finishes the builder into an Arrow list array and resets it for reuse.
    fn finish(&mut self) -> ArrayRef {
        match self {
            Self::Names(builder) | Self::Types(builder) | Self::Sha256(builder) => {
                Arc::new(builder.finish())
            },
            Self::Sizes(builder) => Arc::new(builder.finish()),
        }
    }

    /// Empty builder for the per-message list of attachment sizes.
    fn sizes() -> Self {
        Self::Sizes(ListBuilder::new(UInt64Builder::new()))
    }
}

#[derive(Debug, Clone, Copy)]
/// Which address header an address column reads.
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

impl Slot {
    /// Appends this slot's value for `record`; absent or unparsed data becomes null or an empty
    /// list, never an error.
    fn append(&mut self, record: &Record<'_>) {
        let mail = record.mail;
        match self {
            Self::Position(builder) => builder.append_value(widen(record.position)),
            Self::Offset(builder) => builder.append_value(widen(record.span.start)),
            Self::Size(builder) => builder.append_value(widen(record.span.len())),
            Self::Addresses(header, builder) => append_addresses(builder, *header, mail),
            Self::Subject(builder) => builder.append_option(mail.and_then(Mail::subject)),
            Self::Date(builder) => builder.append_option(date_micros(mail)),
            Self::DateOffset(builder) => builder.append_option(date_offset_minutes(mail)),
            Self::MessageId(builder) => builder.append_option(mail.and_then(Mail::message_id)),
            Self::HeaderValues(name, builder) => append_header_values(builder, name, mail),
            Self::FirstHeaderValue(name, builder) => {
                builder.append_option(first_header_value(name, mail));
            },
            Self::Text(builder) => builder.append_option(mail.map(text_body)),
            Self::Html(builder) => builder.append_option(mail.map(html_body)),
            Self::Attachments(slot) => slot.append(mail),
        }
    }

    /// Finishes the builder into an Arrow array and resets it for reuse.
    fn finish(&mut self) -> ArrayRef {
        match self {
            Self::Position(builder) | Self::Offset(builder) | Self::Size(builder) => {
                Arc::new(builder.finish())
            },
            Self::Addresses(_, builder) | Self::HeaderValues(_, builder) => {
                Arc::new(builder.finish())
            },
            Self::Subject(builder)
            | Self::MessageId(builder)
            | Self::FirstHeaderValue(_, builder)
            | Self::Text(builder)
            | Self::Html(builder) => Arc::new(builder.finish()),
            Self::Date(builder) => Arc::new(builder.finish()),
            Self::DateOffset(builder) => Arc::new(builder.finish()),
            Self::Attachments(slot) => slot.finish(),
        }
    }

    /// A slot collecting only the first value of the header `name` (lowercase) per message.
    fn first_header_value(name: &str) -> Self {
        Self::FirstHeaderValue(name.to_owned(), StringBuilder::new())
    }

    /// A slot collecting every value of the header `name` (lowercase) as a list per message.
    fn header_values(name: &str) -> Self {
        Self::HeaderValues(name.to_owned(), text_list())
    }

    /// Builds the slot matching `column`, preallocating `rows` entries where the builder
    /// supports it.
    fn new(column: &Column, rows: usize) -> Self {
        let addresses = |header| Self::Addresses(header, text_list());
        let attachments = |slot| Self::Attachments(slot);
        match column {
            Column::Position => Self::Position(UInt64Builder::with_capacity(rows)),
            Column::Offset => Self::Offset(UInt64Builder::with_capacity(rows)),
            Column::Size => Self::Size(UInt64Builder::with_capacity(rows)),
            Column::From => addresses(AddressHeader::From),
            Column::To => addresses(AddressHeader::To),
            Column::Cc => addresses(AddressHeader::Cc),
            Column::ReplyTo => addresses(AddressHeader::ReplyTo),
            Column::Subject => Self::Subject(StringBuilder::new()),
            Column::Date => Self::Date(utc_timestamps(rows)),
            Column::DateOffsetMinutes => Self::DateOffset(Int32Builder::with_capacity(rows)),
            Column::MessageId => Self::MessageId(StringBuilder::new()),
            Column::Received => Self::header_values("received"),
            Column::AuthenticationResults => Self::header_values("authentication-results"),
            Column::ReceivedSpf => Self::header_values("received-spf"),
            Column::DkimSignature => Self::header_values("dkim-signature"),
            Column::ReturnPath => Self::first_header_value("return-path"),
            Column::Text => Self::Text(StringBuilder::new()),
            Column::Html => Self::Html(StringBuilder::new()),
            Column::AttachmentNames => attachments(AttachmentSlot::Names(text_list())),
            Column::AttachmentTypes => attachments(AttachmentSlot::Types(text_list())),
            Column::AttachmentSizes => attachments(AttachmentSlot::sizes()),
            Column::AttachmentSha256 => attachments(AttachmentSlot::Sha256(text_list())),
            Column::Header(name) => Self::header_values(name),
        }
    }
}

/// Empty builder for a list of nullable strings.
fn text_list() -> ListBuilder<StringBuilder> {
    ListBuilder::new(StringBuilder::new())
}

/// Narrows `positions` to the messages that exist in a mailbox of `len` messages. A range that
/// starts past the end becomes empty and sits at the end, never inverted.
fn clamp_positions(positions: Range<usize>, len: usize) -> Range<usize> {
    let end = positions.end.min(len);
    positions.start.min(end)..end
}

/// Sends `batches` to `sender` in order until they run out or the receiver is gone.
fn forward_batches(
    batches: impl Iterator<Item = Result<RecordBatch, MboxturboError>>,
    sender: &SyncSender<Result<RecordBatch, MboxturboError>>,
) {
    for batch in batches {
        // A send fails only once the receiver is dropped, and the consumer drops it only after
        // `try_fold` stopped on an `Err`, which `rows` returns.
        if sender.send(batch).is_err() {
            break;
        }
    }
}

/// Wraps a Parquet encoding failure with the output `path` it concerns.
fn parquet_failure(path: &Path, source: ParquetError) -> MboxturboError {
    MboxturboError::Parquet {
        path: path.to_path_buf(),
        source,
    }
}

/// Picks the shallowest parse that serves `columns`: whole message if any needs the body, none if
/// no column needs parsing, otherwise headers only, with just the needed ones decoded.
fn depth_for(columns: &[Column]) -> Depth {
    if columns.iter().any(Column::needs_body) {
        return Depth::Whole(builtin_table_with_raw_received(MessageParser::new()));
    }
    if !columns.iter().any(Column::needs_parsing) {
        return Depth::Nothing;
    }
    let ignoring_the_rest = MessageParser::new().unknown_headers(HeaderForm::Ignore);
    Depth::Headers(columns.iter().fold(ignoring_the_rest, |parser, column| {
        match header_form(column) {
            Some((name, form)) => parser.header(name, form),
            None => parser,
        }
    }))
}

/// The header `column` reads and how to decode it, or `None` when the column needs no header
/// decoded: it reads the raw bytes, offsets, the body, or a header kept as raw text.
const fn header_form(column: &Column) -> Option<(HeaderName<'static>, HeaderForm)> {
    match column {
        Column::From => Some((HeaderName::From, HeaderForm::Addresses)),
        Column::To => Some((HeaderName::To, HeaderForm::Addresses)),
        Column::Cc => Some((HeaderName::Cc, HeaderForm::Addresses)),
        Column::ReplyTo => Some((HeaderName::ReplyTo, HeaderForm::Addresses)),
        Column::Subject => Some((HeaderName::Subject, HeaderForm::Text)),
        Column::Date | Column::DateOffsetMinutes => Some((HeaderName::Date, HeaderForm::Date)),
        Column::MessageId => Some((HeaderName::MessageId, HeaderForm::MessageIds)),
        Column::Position
        | Column::Offset
        | Column::Size
        | Column::Received
        | Column::AuthenticationResults
        | Column::ReceivedSpf
        | Column::DkimSignature
        | Column::ReturnPath
        | Column::Text
        | Column::Html
        | Column::AttachmentNames
        | Column::AttachmentTypes
        | Column::AttachmentSizes
        | Column::AttachmentSha256
        | Column::Header(_) => None,
    }
}

/// Maps the public [`Compression`] choice to the Parquet writer's codec (Zstd at its default
/// level).
fn parquet_compression(compression: Compression) -> ParquetCompression {
    match compression {
        Compression::Zstd => ParquetCompression::ZSTD(ZstdLevel::default()),
        Compression::Snappy => ParquetCompression::SNAPPY,
        Compression::Uncompressed => ParquetCompression::UNCOMPRESSED,
    }
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

/// The Date header of `mail` as UTC microseconds, or `None` when unparsed, absent or invalid.
fn date_micros(mail: Option<&Mail<'_>>) -> Option<i64> {
    mail.and_then(fields::date)
        .map(|date| micros(date.unix_seconds))
}

/// Minutes east of UTC in the Date header of `mail`, or `None` when unparsed, absent or invalid.
fn date_offset_minutes(mail: Option<&Mail<'_>>) -> Option<i32> {
    mail.and_then(fields::date).map(|date| date.offset_minutes)
}

/// The plain-text bodies of `mail` joined by newlines.
fn text_body(mail: &Mail<'_>) -> String {
    joined(fields::text_bodies(mail))
}

/// The HTML bodies of `mail` joined by newlines.
fn html_body(mail: &Mail<'_>) -> String {
    joined(fields::html_bodies(mail))
}

// `fields::date` only yields years 1900..=3000 (`DateTime::is_valid`), so `unix_seconds` stays
// below 4e10 and the product below 4e16: the saturation is unreachable.
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
    use std::iter;
    use std::sync::Arc;
    use std::sync::mpsc::sync_channel;

    use arrow_array::builder::{ListBuilder, StringBuilder};
    use arrow_array::cast::AsArray as _;
    use arrow_array::{Array as _, Int32Array, ListArray, RecordBatch};
    use arrow_schema::{DataType, Field, Schema, TimeUnit};
    use mail_parser::{HeaderForm, HeaderName, MessageParser};

    use super::{
        AddressHeader, AttachmentSlot, Depth, Slot, append_addresses, append_header_values,
        clamp_positions, date_micros, date_offset_minutes, depth_for, first_header_value,
        forward_batches, header_form, html_body, joined, text_body, utc_timestamps,
    };
    use crate::columns::Column;
    use crate::error::MboxturboError;
    use crate::fields::Mail;

    const MULTIPART: &[u8] = b"From: a@example.org\r\nTo: b@example.org, c@example.org\r\n\
Cc: d@example.org\r\nReply-To: e@example.org\r\nReceived: first\r\nReceived: second\r\n\
Date: Thu, 01 Jan 1970 00:00:10 +0130\r\n\
Content-Type: multipart/alternative; boundary=\"b\"\r\n\r\n\
--b\r\nContent-Type: text/plain\r\n\r\nplain part\r\n--b\r\nContent-Type: text/html\r\n\r\n\
<p>html part</p>\r\n--b--\r\n";

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

    fn batch_of(rows: usize) -> RecordBatch {
        let schema = Arc::new(Schema::new(vec![Field::new("n", DataType::Int32, false)]));
        RecordBatch::try_new(schema, vec![Arc::new(Int32Array::from(vec![0; rows]))])
            .expect("fixture batch matches its schema")
    }

    #[test]
    fn positions_past_the_end_are_clamped_to_the_messages_that_exist() {
        assert_eq!(clamp_positions(2..99, 5), 2..5, "end is cut to the length");
    }

    #[test]
    fn a_range_starting_past_the_end_becomes_empty_at_the_end() {
        assert_eq!(clamp_positions(9..12, 5), 5..5, "start must not exceed end");
    }

    #[test]
    fn positions_inside_the_mailbox_are_unchanged() {
        assert_eq!(clamp_positions(1..3, 5), 1..3, "in-range input is kept");
    }

    #[test]
    fn forwarding_delivers_every_batch_in_order() {
        let (sender, receiver) = sync_channel(8);
        forward_batches((1..=3).map(|rows| Ok(batch_of(rows))), &sender);
        drop(sender);
        let sizes: Vec<_> = receiver
            .into_iter()
            .map(|batch| batch.expect("fixture batches are Ok").num_rows())
            .collect();
        assert_eq!(sizes, [1, 2, 3], "batches arrive in production order");
    }

    #[test]
    fn forwarding_stops_pulling_once_the_receiver_is_gone() {
        let (sender, receiver) = sync_channel(1);
        drop(receiver);
        let mut pulled = 0_usize;
        let batches = iter::repeat_with(|| {
            pulled += 1;
            Ok::<_, MboxturboError>(batch_of(1))
        });
        forward_batches(batches.take(10), &sender);
        assert_eq!(pulled, 1, "the failed first send ends extraction");
    }

    #[test]
    fn a_header_column_maps_to_its_header_and_decoding() {
        assert!(
            matches!(
                header_form(&Column::Subject),
                Some((HeaderName::Subject, HeaderForm::Text))
            ),
            "Subject is decoded as text"
        );
        assert!(
            matches!(
                header_form(&Column::DateOffsetMinutes),
                Some((HeaderName::Date, HeaderForm::Date))
            ),
            "the offset column reads the Date header"
        );
    }

    #[test]
    fn columns_that_read_no_decoded_header_map_to_none() {
        assert!(header_form(&Column::Position).is_none(), "position is raw");
        assert!(
            header_form(&Column::Received).is_none(),
            "received stays raw"
        );
    }

    #[test]
    fn raw_columns_need_no_parsing() {
        assert!(
            matches!(depth_for(&[Column::Position, Column::Size]), Depth::Nothing),
            "no message is parsed"
        );
    }

    #[test]
    fn header_columns_parse_headers_only() {
        assert!(
            matches!(
                depth_for(&[Column::Position, Column::Subject]),
                Depth::Headers(_)
            ),
            "a header column parses headers"
        );
    }

    #[test]
    fn a_body_column_forces_a_whole_message_parse() {
        assert!(
            matches!(depth_for(&[Column::Subject, Column::Text]), Depth::Whole(_)),
            "a body column parses the body"
        );
    }

    #[test]
    fn each_address_header_reads_its_own_header() {
        let mail = parse(MULTIPART);
        let read = |header| address_cells(header, Some(&mail));
        assert_eq!(read(AddressHeader::From), ["a@example.org"], "From");
        assert_eq!(
            read(AddressHeader::To),
            ["b@example.org", "c@example.org"],
            "To keeps every address"
        );
        assert_eq!(read(AddressHeader::Cc), ["d@example.org"], "Cc");
        assert_eq!(read(AddressHeader::ReplyTo), ["e@example.org"], "Reply-To");
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
            "absent header"
        );
        assert_eq!(
            first_header_value("received", None),
            None,
            "unparsed message"
        );
    }

    #[test]
    fn the_date_header_gives_utc_microseconds_and_a_minute_offset() {
        let mail = parse(MULTIPART);
        assert_eq!(
            date_micros(Some(&mail)),
            Some(-5_390_000_000),
            "00:00:10 at +01:30 is 5390 seconds before the epoch"
        );
        assert_eq!(
            date_offset_minutes(Some(&mail)),
            Some(90_i32),
            "+0130 is 90 minutes east"
        );
    }

    #[test]
    fn an_unparsed_message_has_no_date() {
        assert_eq!(date_micros(None), None, "no micros without a message");
        assert_eq!(
            date_offset_minutes(None),
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

    #[test]
    fn date_slots_are_built_in_utc() {
        let array = utc_timestamps(1).finish();
        assert_eq!(
            array.data_type(),
            &DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
            "timestamps carry the UTC zone"
        );
    }

    fn header_slot_name(column: &Column) -> Option<String> {
        if let Slot::HeaderValues(name, _) | Slot::FirstHeaderValue(name, _) = Slot::new(column, 0)
        {
            Some(name)
        } else {
            None
        }
    }

    #[test]
    fn header_columns_get_slots_named_by_their_lowercase_header() {
        let named = |column| header_slot_name(&column);
        assert_eq!(
            named(Column::DkimSignature).as_deref(),
            Some("dkim-signature"),
            "list slot"
        );
        assert_eq!(
            named(Column::ReturnPath).as_deref(),
            Some("return-path"),
            "single slot"
        );
        assert_eq!(
            named(Column::Header("x-a".to_owned())).as_deref(),
            Some("x-a"),
            "custom"
        );
    }

    #[test]
    fn return_path_keeps_only_the_first_value_while_received_keeps_all() {
        assert!(
            matches!(
                Slot::new(&Column::ReturnPath, 0),
                Slot::FirstHeaderValue(..)
            ),
            "return-path is a single-value slot"
        );
        assert!(
            matches!(Slot::new(&Column::Received, 0), Slot::HeaderValues(..)),
            "received is a list slot"
        );
    }

    #[test]
    fn the_attachment_sizes_column_gets_a_size_list_slot() {
        assert!(
            matches!(
                Slot::new(&Column::AttachmentSizes, 0),
                Slot::Attachments(AttachmentSlot::Sizes(_))
            ),
            "sizes are numeric lists"
        );
    }
}
