//! Columnar extraction: parse only what the selected columns need, in parallel, into Arrow
//! record batches, and stream them to a consumer. See [`Export`](crate::Export) and
//! [`ParquetExporter`](crate::ParquetExporter) for files.

use std::borrow::Cow;
use std::cell::OnceCell;
use std::fmt::Debug;
use std::ops::Range;
use std::sync::Arc;

use arrow_array::builder::{
    Int32Builder, LargeBinaryBuilder, ListBuilder, StringBuilder, TimestampMicrosecondBuilder,
    UInt64Builder,
};
use arrow_array::{ArrayRef, RecordBatch, RecordBatchReader};
use arrow_schema::{ArrowError, Schema, SchemaRef};
use mail_parser::{AddressList, HeaderForm, HeaderName, MessageParser};
use mboxturbo_headers::{AuthMethod, TrustSet};
use sha2::{Digest as _, Sha256};

use crate::columns::Column;
use crate::error::MboxTurboError;
use crate::fields::{
    self, Mail, builtin_table_with_raw_received, contain_parser_panic, strip_separator,
};
use crate::mailbox::Mailbox;
use crate::message::Timestamp;
use crate::selection::{Plan, Selection};
use crate::stream::Ordered;
use crate::structured::{
    ArcSetsColumn, AuthResultsColumn, DkimSignaturesColumn, MicrosoftAntispamColumn,
    ReceivedHopsColumn, ReceivedSpfColumn, VerdictColumn,
};
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
    /// Called as each extraction job starts, so tests can observe and hold jobs.
    #[cfg(test)]
    probe: Option<Arc<dyn Probe>>,
    /// Arrow schema derived from `columns`, shared by every batch.
    schema: SchemaRef,
    /// The trust set deciding the `trusted` flags of the structured columns; without one they
    /// are null.
    trust: Option<Arc<TrustSet>>,
}

/// A test hook told which runs each extraction job covers as the job starts.
#[cfg(test)]
trait Probe: Debug + Send + Sync {
    /// Called on the pool thread before the job extracts `runs`; may block to hold the job.
    fn started(&self, runs: &[Range<usize>]);
}

/// One message as seen by the column builders: where it sits in the mailbox and its parsed form.
pub(crate) struct Record<'mail> {
    /// The `Date` header, read from `raw` on first use so two date columns share one read.
    date: OnceCell<Option<Timestamp>>,
    /// Parsed message, or `None` when no column needs parsing or the parser rejected or panicked
    /// on it.
    mail: Option<&'mail Mail<'mail>>,
    /// Zero-based index of the message in the mailbox.
    position: usize,
    /// The message's stored bytes, separator line included.
    raw: &'mail [u8],
    /// Byte range of the message in the mailbox file.
    span: Range<usize>,
    /// The trust set of the pipeline, if it has one.
    trust: Option<&'mail TrustSet>,
}

impl<'mail> Record<'mail> {
    /// The message's `Date` header, read from the raw bytes at most once.
    fn date(&self) -> Option<Timestamp> {
        *self.date.get_or_init(|| fields::date(self.raw))
    }

    /// The parsed message, or `None` when no column needs parsing or the parser rejected it.
    pub(crate) const fn mail(&self) -> Option<&'mail Mail<'mail>> {
        self.mail
    }

    /// The trust set of the pipeline, if it has one.
    pub(crate) const fn trust(&self) -> Option<&'mail TrustSet> {
        self.trust
    }
}

/// Batches over a selection of a mailbox, extracted on all rayon threads and handed over in
/// selection order as soon as each is ready.
#[derive(Debug)]
pub struct BatchReader {
    /// Mailbox being read.
    mailbox: Arc<Mailbox>,
    /// Pipeline that decides columns, schema and batch size.
    pipeline: Arc<Pipeline>,
    /// The selected positions not yet scheduled for extraction.
    plan: Plan,
    /// Batches scheduled or extracted, in selection order, awaiting delivery.
    stream: Ordered<Result<RecordBatch, MboxTurboError>>,
}

impl Pipeline {
    /// Extracts the messages at `positions` (clamped to those that exist) into one batch.
    ///
    /// # Errors
    ///
    /// [`MboxTurboError::Arrow`], naming the clamped positions, if the columns cannot be
    /// assembled into a batch.
    pub fn extract(
        &self,
        mailbox: &Mailbox,
        positions: Range<usize>,
    ) -> Result<RecordBatch, MboxTurboError> {
        let clamped = mailbox.clamped(positions);
        self.extract_runs(mailbox, &[clamped])
    }

    /// Extracts the messages of each run in `runs`, in order, into one batch. Every run must lie
    /// within the mailbox.
    ///
    /// # Errors
    ///
    /// [`MboxTurboError::Arrow`], naming the smallest range covering every run, if the columns
    /// cannot be assembled into a batch.
    fn extract_runs(
        &self,
        mailbox: &Mailbox,
        runs: &[Range<usize>],
    ) -> Result<RecordBatch, MboxTurboError> {
        let rows = runs.iter().map(Range::len).fold(0, usize::saturating_add);
        let mut builders: Vec<Box<dyn ColumnBuilder>> = self
            .columns
            .iter()
            .map(|column| column_builder(column, rows))
            .collect();
        for (position, span, raw) in runs.iter().flat_map(|run| mailbox.rows(run.clone())) {
            let parsed = self.parse(raw);
            let record = Record {
                date: OnceCell::new(),
                position,
                raw,
                span,
                mail: parsed.as_ref(),
                trust: self.trust.as_deref(),
            };
            for builder in &mut builders {
                builder.append(&record);
            }
        }
        let batch = builders
            .iter_mut()
            .map(|builder| builder.finish())
            .collect::<Result<Vec<ArrayRef>, ArrowError>>()
            .and_then(|arrays| RecordBatch::try_new(self.schema(), arrays));
        batch.map_err(|source| MboxTurboError::Arrow {
            positions: covering(runs),
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
            #[cfg(test)]
            probe: None,
            trust: None,
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
            plan: Plan::whole(mailbox.len()),
            stream: Ordered::new(),
        }
    }

    /// Extracts `runs` on a pool thread; the only entry of an extraction job.
    fn run_job(
        &self,
        mailbox: &Mailbox,
        runs: &[Range<usize>],
    ) -> Result<RecordBatch, MboxTurboError> {
        #[cfg(test)]
        if let Some(probe) = &self.probe {
            probe.started(runs);
        }
        self.extract_runs(mailbox, runs)
    }

    /// The Arrow schema of every batch this pipeline produces.
    #[must_use]
    pub fn schema(&self) -> SchemaRef {
        Arc::clone(&self.schema)
    }

    /// Streams batches over the messages `selection` names, in the order it gives them,
    /// extracting several batches in parallel at a time.
    ///
    /// # Errors
    ///
    /// [`MboxTurboError::PositionOutOfRange`] naming the first position at or past the end of
    /// `mailbox`; no message is read in that case.
    pub fn select(
        self: &Arc<Self>,
        mailbox: &Arc<Mailbox>,
        selection: Selection,
    ) -> Result<BatchReader, MboxTurboError> {
        Ok(BatchReader {
            pipeline: Arc::clone(self),
            mailbox: Arc::clone(mailbox),
            plan: selection.plan(mailbox.len())?,
            stream: Ordered::new(),
        })
    }

    /// Sets the trust set that decides the `trusted` flag of the `auth_results` and `arc_sets`
    /// columns and the `verdict_*` columns. Without one every flag and verdict is null.
    #[must_use]
    pub fn with_trust(mut self, trust: TrustSet) -> Self {
        self.trust = Some(Arc::new(trust));
        self
    }
}

impl BatchReader {
    /// Schedules batches until about two per rayon thread are in flight or the plan runs out,
    /// asking the kernel to read the batch after each one in the background.
    fn fill(&mut self) {
        let in_flight = rayon::current_num_threads().saturating_mul(2);
        while self.stream.in_flight() < in_flight {
            let runs = self.plan.take(self.pipeline.batch_size);
            if runs.is_empty() {
                break;
            }
            for ahead in self.plan.clone().take(self.pipeline.batch_size) {
                self.mailbox.prefetch(ahead);
            }
            let pipeline = Arc::clone(&self.pipeline);
            let mailbox = Arc::clone(&self.mailbox);
            self.stream
                .submit(move || pipeline.run_job(&mailbox, &runs));
        }
    }

    /// The next batch, keeping the typed error so callers can read the positions it covers.
    pub(crate) fn next_batch(&mut self) -> Option<Result<RecordBatch, MboxTurboError>> {
        self.fill();
        let batch = self.stream.next();
        self.fill();
        batch
    }

    /// The number of messages the selection yields in total, whatever has been read so far.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.plan.total()
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

/// Boxes `builder` as a [`ColumnBuilder`].
fn boxed(builder: impl ColumnBuilder + 'static) -> Box<dyn ColumnBuilder> {
    Box::new(builder)
}

/// The builder of `column`, preallocating `rows` entries where the builder supports it. The only
/// place that switches on the column.
#[expect(
    clippy::too_many_lines,
    reason = "one arm per column keeps the match exhaustive, so no column is forgotten"
)]
fn column_builder(column: &Column, rows: usize) -> Box<dyn ColumnBuilder> {
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

/// The smallest range covering every run in `runs`.
fn covering(runs: &[Range<usize>]) -> Range<usize> {
    let start = runs.iter().map(|run| run.start).min().unwrap_or(0);
    let end = runs.iter().map(|run| run.end).max().unwrap_or(0);
    start..end
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
fn header_form(column: &Column) -> Option<(HeaderName<'static>, HeaderForm)> {
    column.header_form()
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
    use std::io::{Write as _, sink};
    use std::iter;
    use std::ops::Range;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::{Receiver, channel};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use arrow_array::builder::{ListBuilder, StringBuilder};
    use arrow_array::cast::AsArray as _;
    use arrow_array::types::{TimestampMicrosecondType, UInt64Type};
    use arrow_array::{Array as _, ArrayRef, ListArray, RecordBatch};
    use arrow_schema::{DataType, Field, Schema, SchemaRef, TimeUnit};
    use mail_parser::{HeaderForm, HeaderName, MessageParser};
    use tempfile::NamedTempFile;

    use super::{
        AddressHeader, Depth, Pipeline, Probe, Record, append_addresses, append_header_values,
        column_builder, depth_for, first_header_value, header_form, html_body, joined, micros,
        text_body,
    };
    use crate::columns::Column;
    use crate::error::MboxTurboError;
    use crate::export::{Export, Exporter};
    use crate::fields;
    use crate::fields::Mail;
    use crate::mailbox::Mailbox;
    use crate::selection::Selection;
    use crate::staging::{Destination, DestinationKind, Staged};

    /// A bound only a broken implementation reaches: it turns a hang into a failure.
    const STUCK: Duration = Duration::from_secs(60);

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

    /// Holds the extraction job whose first message is `held_start` until the test releases it.
    #[derive(Debug)]
    struct Hold {
        gate: Mutex<Receiver<()>>,
        held_start: usize,
    }

    impl Probe for Hold {
        fn started(&self, runs: &[Range<usize>]) {
            if runs.first().map(|run| run.start) != Some(self.held_start) {
                return;
            }
            self.gate
                .lock()
                .expect("no job panics while holding the gate")
                .recv_timeout(STUCK)
                .expect("the test releases the held job after reading the first batch");
        }
    }

    /// Counts the extraction jobs that have started.
    #[derive(Debug, Default)]
    struct Started(AtomicUsize);

    impl Probe for Started {
        fn started(&self, _runs: &[Range<usize>]) {
            let _previous = self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Accepts any destination and writes nothing, so only the reader can fail an export.
    #[derive(Debug)]
    struct Discard;

    impl Exporter for Discard {
        fn accepts(&self, _kind: DestinationKind) -> bool {
            true
        }

        fn begin(
            &mut self,
            _schema: &SchemaRef,
            _staged: &mut Staged,
        ) -> Result<(), MboxTurboError> {
            Ok(())
        }

        fn finish(&mut self, _staged: &mut Staged) -> Result<u64, MboxTurboError> {
            Ok(0)
        }

        fn write(
            &mut self,
            _batch: &RecordBatch,
            _staged: &mut Staged,
        ) -> Result<u64, MboxTurboError> {
            Ok(0)
        }
    }

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
    fn every_decoded_header_column_maps_to_its_header_and_decoding() {
        let table = [
            (Column::From, HeaderName::From, HeaderForm::Addresses),
            (Column::To, HeaderName::To, HeaderForm::Addresses),
            (Column::Cc, HeaderName::Cc, HeaderForm::Addresses),
            (Column::ReplyTo, HeaderName::ReplyTo, HeaderForm::Addresses),
            (Column::Subject, HeaderName::Subject, HeaderForm::Text),
            (
                Column::MessageId,
                HeaderName::MessageId,
                HeaderForm::MessageIds,
            ),
        ];
        for (column, name, form) in table {
            assert_eq!(
                header_form(&column),
                Some((name, form)),
                "{column:?} must read its own header with its own decoding"
            );
        }
    }

    #[test]
    fn columns_that_read_no_decoded_header_map_to_none() {
        assert!(header_form(&Column::Position).is_none(), "position is raw");
        assert!(
            header_form(&Column::Received).is_none(),
            "received stays raw"
        );
        for column in [Column::Date, Column::DateOffsetMinutes] {
            assert!(
                header_form(&column).is_none(),
                "{column:?} reads the raw bytes, so no Date decode"
            );
        }
    }

    #[test]
    fn raw_columns_need_no_parsing() {
        assert!(
            matches!(depth_for(&[Column::Position, Column::Size]), Depth::Nothing),
            "no message is parsed"
        );
        assert!(
            matches!(depth_for(&[Column::Raw]), Depth::Nothing),
            "raw alone parses no message"
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
    fn header_columns_get_slots_named_by_their_lowercase_header() {
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

    #[test]
    fn a_batch_that_cannot_be_assembled_reports_the_clamped_positions() {
        let mut file = NamedTempFile::new().expect("temp file is created");
        file.write_all(b"From a@x Mon Jan  1 00:00:00 2024\nSubject: one\n\nfirst\n")
            .expect("fixture mbox is written");
        let mailbox = Mailbox::open(file.path()).expect("fixture mbox opens");
        let mut pipeline = Pipeline::new(vec![Column::Position], 1);
        pipeline.schema = Arc::new(Schema::new(Vec::<Field>::new()));
        let error = pipeline
            .extract(&mailbox, 0..99)
            .expect_err("one array cannot fill a zero-field schema");
        assert!(
            matches!(&error, MboxTurboError::Arrow { positions, .. } if *positions == (0..1)),
            "the error names the positions clamped to the one message that exists"
        );
    }

    // Only a batch that cannot be assembled fails a reader once `select` has succeeded, and
    // the public API cannot build one, so the schema is replaced here as in the test above.
    #[test]
    fn a_reader_error_reaches_the_export_caller_as_its_own_variant_and_positions() {
        let (_file, mailbox) = numbered_mailbox(3);
        let mut pipeline = Pipeline::new(vec![Column::Position], 2);
        pipeline.schema = Arc::new(Schema::new(Vec::<Field>::new()));
        let error = Export::new(
            Arc::new(pipeline),
            mailbox,
            Destination::Stream(Box::new(sink())),
        )
        .selection(Selection::Positions(vec![1, 2]))
        .run(Box::new(Discard))
        .expect_err("a batch that cannot be assembled fails the export");
        assert!(
            matches!(&error, MboxTurboError::Arrow { positions, .. } if *positions == (1..3)),
            "the driver returns the reader's error naming the selected positions: {error:?}"
        );
    }

    fn numbered_mailbox(count: usize) -> (NamedTempFile, Arc<Mailbox>) {
        let mut file = NamedTempFile::new().expect("temp file is created");
        for index in 0..count {
            write!(
                file,
                "From x Mon Jan  1 00:00:00 2024\nSubject: s{index}\n\nb\n"
            )
            .expect("fixture mbox is written");
        }
        let mailbox = Arc::new(Mailbox::open(file.path()).expect("fixture mbox opens"));
        (file, mailbox)
    }

    #[test]
    fn a_reader_returns_the_first_batch_while_a_later_batch_of_its_window_is_unfinished() {
        let (_file, mailbox) = numbered_mailbox(20);
        let (release, gate) = channel::<()>();
        let mut pipeline = Pipeline::new(vec![Column::Position], 1);
        pipeline.probe = Some(Arc::new(Hold {
            gate: Mutex::new(gate),
            held_start: 1,
        }));
        let mut reader = Arc::new(pipeline).reader(&mailbox);
        let first = reader
            .next()
            .expect("a first batch exists")
            .expect("it is assembled");
        assert_eq!(
            first.num_rows(),
            1,
            "the first batch is returned although the second is still held in its window"
        );
        release.send(()).expect("the held job is still waiting");
        let rest = reader.map(|batch| batch.expect("every batch is assembled").num_rows());
        assert_eq!(
            rest.sum::<usize>(),
            19,
            "the remaining batches arrive once the held one finishes"
        );
    }

    #[test]
    fn dropping_a_reader_stops_extraction_from_starting_on_its_queued_batches() {
        let (_file, mailbox) = numbered_mailbox(200);
        let started = Arc::new(Started::default());
        let probe: Arc<dyn Probe> = Arc::<Started>::clone(&started);
        let mut plan = Pipeline::new(vec![Column::Position], 1);
        plan.probe = Some(probe);
        let pipeline = Arc::new(plan);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .expect("test thread pool builds");
        let at_drop = pool.install(|| {
            let mut reader = pipeline.reader(&mailbox);
            let _first = reader
                .next()
                .expect("a first batch exists")
                .expect("it is assembled");
            drop(reader);
            started.0.load(Ordering::SeqCst)
        });
        let (done, finished) = channel::<()>();
        pool.spawn(move || done.send(()).expect("the test waits for the pool to drain"));
        finished
            .recv_timeout(STUCK)
            .expect("the pool drains its queue after the reader is dropped");
        assert_eq!(
            started.0.load(Ordering::SeqCst),
            at_drop,
            "no extraction job started after the reader was dropped"
        );
    }
}
