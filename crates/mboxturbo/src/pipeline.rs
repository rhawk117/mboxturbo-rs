//! Columnar extraction: parse only what the selected columns need, in parallel, into Arrow
//! record batches, and stream them to a consumer. See [`Export`](crate::Export) and
//! [`ParquetExporter`](crate::ParquetExporter) for files.

mod slots;

use std::cell::OnceCell;
use std::fmt::Debug;
use std::ops::Range;
use std::sync::Arc;

use arrow_array::{ArrayRef, RecordBatch, RecordBatchReader};
use arrow_schema::{ArrowError, Schema, SchemaRef};
use mail_parser::{HeaderForm, HeaderName, MessageParser};
use mboxturbo_headers::TrustSet;
pub(crate) use slots::ColumnBuilder;
use slots::column_builder;

use crate::columns::Column;
use crate::error::MboxTurboError;
use crate::fields::{
    self, Mail, builtin_table_with_raw_received, contain_parser_panic, strip_separator,
};
use crate::mailbox::Mailbox;
use crate::message::Timestamp;
use crate::selection::{Plan, Selection};
use crate::stream::Ordered;

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

#[cfg(test)]
mod tests {
    use std::io::{Write as _, sink};
    use std::ops::Range;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::{Receiver, channel};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use arrow_array::RecordBatch;
    use arrow_schema::{Field, Schema, SchemaRef};
    use mail_parser::{HeaderForm, HeaderName};
    use tempfile::NamedTempFile;

    use super::{Depth, Pipeline, Probe, depth_for, header_form};
    use crate::columns::Column;
    use crate::error::MboxTurboError;
    use crate::export::{Export, Exporter};
    use crate::mailbox::Mailbox;
    use crate::selection::Selection;
    use crate::staging::{Destination, DestinationKind, Staged};

    /// A bound only a broken implementation reaches: it turns a hang into a failure.
    const STUCK: Duration = Duration::from_secs(60);

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
