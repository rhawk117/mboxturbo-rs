//! Columnar extraction: parse only what the selected columns need, in parallel, into Arrow
//! record batches, and stream them to a consumer or a Parquet file.

use std::collections::VecDeque;
use std::fs::File;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::sync_channel;
use std::thread;

use arrow_array::builder::{
    Int32Builder, ListBuilder, StringBuilder, TimestampMicrosecondBuilder, UInt64Builder,
};
use arrow_array::{ArrayRef, RecordBatch, RecordBatchReader};
use arrow_schema::{ArrowError, Schema, SchemaRef};
use mail_parser::{HeaderName, MessageParser};
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression as ParquetCompression, ZstdLevel};
use parquet::file::properties::{EnabledStatistics, WriterProperties};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::columns::Column;
use crate::error::Error;
use crate::fields::{
    self, Mail, builtin_table_with_raw_received, contain_parser_panic, strip_separator,
};
use crate::mailbox::Mailbox;
use crate::width::widen;

/// Parquet page compression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Compression {
    /// Zstandard at level 1: a good ratio at close to Snappy speed.
    #[default]
    Zstd,
    /// Snappy.
    Snappy,
    /// No compression.
    Uncompressed,
}

#[derive(Debug)]
enum Depth {
    Nothing,
    Headers(MessageParser),
    Whole(MessageParser),
}

/// A reusable extraction plan: which columns, how deep to parse, and how many rows per batch.
#[derive(Debug)]
pub struct Pipeline {
    columns: Box<[Column]>,
    schema: SchemaRef,
    depth: Depth,
    batch_size: usize,
}

struct Record<'a> {
    position: usize,
    span: Range<usize>,
    mail: Option<&'a Mail<'a>>,
}

impl Pipeline {
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

    /// The Arrow schema of every batch this pipeline produces.
    #[must_use]
    pub fn schema(&self) -> SchemaRef {
        Arc::clone(&self.schema)
    }

    /// Extracts the messages at `positions` (clamped to those that exist) into one batch.
    ///
    /// # Errors
    ///
    /// [`Error::Arrow`] if the columns cannot be assembled into a batch.
    pub fn extract(
        &self,
        mailbox: &Mailbox,
        positions: Range<usize>,
    ) -> Result<RecordBatch, Error> {
        let end = positions.end.min(mailbox.len());
        let positions = positions.start.min(end)..end;
        let mut slots: Vec<Slot> = self
            .columns
            .iter()
            .map(|column| Slot::new(column, positions.len()))
            .collect();
        for position in positions {
            let Some(span) = mailbox.index().span(position) else {
                continue;
            };
            let raw = mailbox.raw(position).unwrap_or_default();
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
        RecordBatch::try_new(self.schema(), arrays).map_err(|source| Error::Arrow { source })
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

    /// Writes every batch to a Parquet file at `path`, atomically, while the next batches are
    /// extracted on other threads. Returns the number of rows written.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the file cannot be created or renamed into place, [`Error::Parquet`]
    /// when encoding fails, and [`Error::Arrow`] if a batch cannot be assembled.
    pub fn write_parquet(
        self: &Arc<Self>,
        mailbox: &Arc<Mailbox>,
        path: &Path,
        compression: Compression,
    ) -> Result<u64, Error> {
        let directory = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty());
        let staged = NamedTempFile::new_in(directory.unwrap_or_else(|| Path::new(".")))
            .map_err(|source| Error::io(path, source))?;
        let file = staged.reopen().map_err(|source| Error::io(path, source))?;
        let rows = self.encode_parquet(mailbox, file, compression, path)?;
        staged
            .persist(path)
            .map_err(|failure| Error::io(path, failure.error))?;
        Ok(rows)
    }

    fn encode_parquet(
        self: &Arc<Self>,
        mailbox: &Arc<Mailbox>,
        file: File,
        compression: Compression,
        path: &Path,
    ) -> Result<u64, Error> {
        let parquet_error = |source| Error::Parquet {
            path: path.to_path_buf(),
            source,
        };
        let properties = WriterProperties::builder()
            .set_compression(parquet_compression(compression))
            .set_max_row_group_row_count(Some(self.batch_size.saturating_mul(16)))
            .set_dictionary_enabled(false)
            .set_statistics_enabled(EnabledStatistics::Chunk)
            .build();
        let mut writer =
            ArrowWriter::try_new(file, self.schema(), Some(properties)).map_err(parquet_error)?;
        let (sender, receiver) = sync_channel(rayon::current_num_threads().saturating_mul(2));
        let mut reader = self.reader(mailbox);
        let produced = thread::scope(|scope| {
            scope.spawn(move || reader.try_for_each(|batch| sender.send(batch).map_err(drop)));
            receiver.iter().try_fold(0_u64, |rows, batch| {
                let batch = batch.map_err(|source| Error::Arrow { source })?;
                writer.write(&batch).map_err(parquet_error)?;
                Ok::<u64, Error>(rows.saturating_add(widen(batch.num_rows())))
            })
        })?;
        writer.close().map_err(parquet_error)?;
        Ok(produced)
    }

    fn parse<'a>(&self, raw: &'a [u8]) -> Option<Mail<'a>> {
        let message = strip_separator(raw);
        match &self.depth {
            Depth::Nothing => None,
            Depth::Headers(parser) => contain_parser_panic(|| parser.parse_headers(message)),
            Depth::Whole(parser) => contain_parser_panic(|| parser.parse(message)),
        }
    }

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
}

fn depth_for(columns: &[Column]) -> Depth {
    if columns.iter().any(Column::needs_body) {
        return Depth::Whole(builtin_table_with_raw_received(MessageParser::new()));
    }
    if !columns.iter().any(Column::needs_parsing) {
        return Depth::Nothing;
    }
    let ignoring_the_rest = MessageParser::new().default_header_ignore();
    Depth::Headers(
        columns
            .iter()
            .fold(ignoring_the_rest, |parser, column| match column {
                Column::From => parser.header_address(HeaderName::From),
                Column::To => parser.header_address(HeaderName::To),
                Column::Cc => parser.header_address(HeaderName::Cc),
                Column::ReplyTo => parser.header_address(HeaderName::ReplyTo),
                Column::Subject => parser.header_text(HeaderName::Subject),
                Column::Date | Column::DateOffsetMinutes => parser.header_date(HeaderName::Date),
                Column::MessageId => parser.header_id(HeaderName::MessageId),
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
                | Column::Header(_) => parser,
            }),
    )
}

fn parquet_compression(compression: Compression) -> ParquetCompression {
    match compression {
        Compression::Zstd => ParquetCompression::ZSTD(ZstdLevel::default()),
        Compression::Snappy => ParquetCompression::SNAPPY,
        Compression::Uncompressed => ParquetCompression::UNCOMPRESSED,
    }
}

/// Batches over a whole mailbox, produced a window at a time on all rayon threads.
#[derive(Debug)]
pub struct BatchReader {
    pipeline: Arc<Pipeline>,
    mailbox: Arc<Mailbox>,
    next: usize,
    ready: VecDeque<Result<RecordBatch, ArrowError>>,
}

impl Iterator for BatchReader {
    type Item = Result<RecordBatch, ArrowError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.ready.is_empty() {
            let window = self.pipeline.window(self.next, &self.mailbox);
            self.next = window.last().map_or(self.next, |last| last.end);
            self.mailbox
                .prefetch(self.next..self.next.saturating_add(self.pipeline.batch_size));
            let extracted: Vec<_> = window
                .into_par_iter()
                .map(|positions| {
                    self.pipeline
                        .extract(&self.mailbox, positions)
                        .map_err(|error| ArrowError::ExternalError(Box::new(error)))
                })
                .collect();
            self.ready.extend(extracted);
        }
        self.ready.pop_front()
    }
}

impl RecordBatchReader for BatchReader {
    fn schema(&self) -> SchemaRef {
        self.pipeline.schema()
    }
}

#[derive(Debug)]
enum Slot {
    Position(UInt64Builder),
    Offset(UInt64Builder),
    Size(UInt64Builder),
    Addresses(AddressHeader, ListBuilder<StringBuilder>),
    Subject(StringBuilder),
    Date(TimestampMicrosecondBuilder),
    DateOffset(Int32Builder),
    MessageId(StringBuilder),
    HeaderValues(String, ListBuilder<StringBuilder>),
    FirstHeaderValue(String, StringBuilder),
    Text(StringBuilder),
    Html(StringBuilder),
    Attachments(AttachmentSlot),
}

#[derive(Debug)]
enum AttachmentSlot {
    Names(ListBuilder<StringBuilder>),
    Types(ListBuilder<StringBuilder>),
    Sizes(ListBuilder<UInt64Builder>),
    Sha256(ListBuilder<StringBuilder>),
}

impl AttachmentSlot {
    fn append(&mut self, mail: Option<&Mail<'_>>) {
        let attachments = mail.into_iter().flat_map(fields::attachments);
        match self {
            Self::Names(builder) => {
                builder
                    .values()
                    .extend(attachments.map(|attachment| attachment.filename));
                builder.append(true);
            }
            Self::Types(builder) => {
                builder
                    .values()
                    .extend(attachments.map(|attachment| attachment.content_type()));
                builder.append(true);
            }
            Self::Sizes(builder) => {
                let sizes = attachments.map(|attachment| Some(widen(attachment.data.len())));
                builder.values().extend(sizes);
                builder.append(true);
            }
            Self::Sha256(builder) => {
                let digests = attachments.map(|attachment| Some(sha256_hex(attachment.data)));
                builder.values().extend(digests);
                builder.append(true);
            }
        }
    }

    fn finish(&mut self) -> ArrayRef {
        match self {
            Self::Names(builder) | Self::Types(builder) | Self::Sha256(builder) => {
                Arc::new(builder.finish())
            }
            Self::Sizes(builder) => Arc::new(builder.finish()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum AddressHeader {
    From,
    To,
    Cc,
    ReplyTo,
}

impl AddressHeader {
    fn of<'a>(self, mail: &'a Mail<'a>) -> Option<&'a mail_parser::Address<'a>> {
        match self {
            Self::From => mail.from(),
            Self::To => mail.to(),
            Self::Cc => mail.cc(),
            Self::ReplyTo => mail.reply_to(),
        }
    }
}

fn text_list() -> ListBuilder<StringBuilder> {
    ListBuilder::new(StringBuilder::new())
}

impl Slot {
    fn new(column: &Column, rows: usize) -> Self {
        let addresses = |header| Self::Addresses(header, text_list());
        match column {
            Column::Position => Self::Position(UInt64Builder::with_capacity(rows)),
            Column::Offset => Self::Offset(UInt64Builder::with_capacity(rows)),
            Column::Size => Self::Size(UInt64Builder::with_capacity(rows)),
            Column::From => addresses(AddressHeader::From),
            Column::To => addresses(AddressHeader::To),
            Column::Cc => addresses(AddressHeader::Cc),
            Column::ReplyTo => addresses(AddressHeader::ReplyTo),
            Column::Subject => Self::Subject(StringBuilder::new()),
            Column::Date => {
                Self::Date(TimestampMicrosecondBuilder::with_capacity(rows).with_timezone("UTC"))
            }
            Column::DateOffsetMinutes => Self::DateOffset(Int32Builder::with_capacity(rows)),
            Column::MessageId => Self::MessageId(StringBuilder::new()),
            Column::Received => Self::HeaderValues("received".to_owned(), text_list()),
            Column::AuthenticationResults => {
                Self::HeaderValues("authentication-results".to_owned(), text_list())
            }
            Column::ReceivedSpf => Self::HeaderValues("received-spf".to_owned(), text_list()),
            Column::DkimSignature => Self::HeaderValues("dkim-signature".to_owned(), text_list()),
            Column::ReturnPath => {
                Self::FirstHeaderValue("return-path".to_owned(), StringBuilder::new())
            }
            Column::Text => Self::Text(StringBuilder::new()),
            Column::Html => Self::Html(StringBuilder::new()),
            Column::AttachmentNames => Self::Attachments(AttachmentSlot::Names(text_list())),
            Column::AttachmentTypes => Self::Attachments(AttachmentSlot::Types(text_list())),
            Column::AttachmentSizes => Self::Attachments(AttachmentSlot::Sizes(ListBuilder::new(
                UInt64Builder::new(),
            ))),
            Column::AttachmentSha256 => Self::Attachments(AttachmentSlot::Sha256(text_list())),
            Column::Header(name) => Self::HeaderValues(name.clone(), text_list()),
        }
    }

    fn append(&mut self, record: &Record<'_>) {
        let mail = record.mail;
        match self {
            Self::Position(builder) => builder.append_value(widen(record.position)),
            Self::Offset(builder) => builder.append_value(widen(record.span.start)),
            Self::Size(builder) => builder.append_value(widen(record.span.len())),
            Self::Addresses(header, builder) => {
                let addresses = fields::addresses(mail.and_then(|mail| header.of(mail)));
                builder
                    .values()
                    .extend(addresses.map(|address| address.email));
                builder.append(true);
            }
            Self::Subject(builder) => builder.append_option(mail.and_then(Mail::subject)),
            Self::Date(builder) => {
                builder.append_option(
                    mail.and_then(fields::date)
                        .map(|date| micros(date.unix_seconds)),
                );
            }
            Self::DateOffset(builder) => {
                builder.append_option(mail.and_then(fields::date).map(|date| date.offset_minutes));
            }
            Self::MessageId(builder) => builder.append_option(mail.and_then(Mail::message_id)),
            Self::HeaderValues(name, builder) => {
                builder.values().extend(
                    mail.into_iter()
                        .flat_map(|mail| fields::header_values(mail, name.as_str()))
                        .map(Some),
                );
                builder.append(true);
            }
            Self::FirstHeaderValue(name, builder) => builder.append_option(
                mail.and_then(|mail| fields::header_values(mail, name.as_str()).next()),
            ),
            Self::Text(builder) => {
                builder.append_option(mail.map(|mail| joined(fields::text_bodies(mail))));
            }
            Self::Html(builder) => {
                builder.append_option(mail.map(|mail| joined(fields::html_bodies(mail))));
            }
            Self::Attachments(slot) => slot.append(mail),
        }
    }

    fn finish(&mut self) -> ArrayRef {
        match self {
            Self::Position(builder) | Self::Offset(builder) | Self::Size(builder) => {
                Arc::new(builder.finish())
            }
            Self::Addresses(_, builder) | Self::HeaderValues(_, builder) => {
                Arc::new(builder.finish())
            }
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
}

const fn micros(unix_seconds: i64) -> i64 {
    unix_seconds.saturating_mul(1_000_000)
}

fn joined<'a>(bodies: impl Iterator<Item = std::borrow::Cow<'a, str>>) -> String {
    bodies.collect::<Vec<_>>().join("\n")
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0F])
        .filter_map(|nibble| char::from_digit(u32::from(nibble), 16))
        .collect()
}
