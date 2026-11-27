//! The column pipeline agrees with the `Message` API, keeps every row in order, and round-trips
//! through Parquet.

#[cfg(test)]
mod pipeline {
    use std::fs::{self, File};
    use std::ops::Range;
    use std::path::PathBuf;
    use std::sync::Arc;

    use arrow_array::cast::AsArray as _;
    use arrow_array::types::{Int32Type, TimestampMicrosecondType, UInt64Type};
    use arrow_array::{Array as _, RecordBatch};
    use mboxturbo::{
        Column, Compression, Destination, Export, Mailbox, MboxTurboError, ParquetExporter,
        Pipeline, Selection,
    };
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use proptest::prelude::*;
    use sha2::{Digest as _, Sha256};
    use tempfile::TempDir;

    const MESSAGES: &str = "From a@example.com Mon Jan  1 00:00:00 2024\n\
From: Jane <jane@example.com>\n\
Subject: first\n\
Received: from mx1\n\tby mx2\n\
Received: from mx3\n\
X-Mailer: forged\n\
\n\
body\n\
\n\
From b@example.com Tue Jan  2 00:00:00 2024\n\
From: bob@example.com\n\
Subject: second\n\
Content-Type: multipart/mixed; boundary=\"B\"\n\
\n\
--B\n\
Content-Type: text/plain\n\
\n\
hello\n\
--B\n\
Content-Type: application/octet-stream; name=\"x.bin\"\n\
Content-Transfer-Encoding: base64\n\
\n\
AAEC\n\
--B--\n";

    const DATE_MIX: [&str; 10] = [
        "Date: Mon, 01 Jan 2024 12:00:00 +0000\n",
        "Date: Mon Jan  1 12:00:00 2024\n",
        "Date: Mon, 01 Jan 2024 12:00:00 EST\n",
        "Date: Mon, 01 Jan 2024 12:00:00 -0500 (EST)\n",
        "Date: Mon, 01 Jan 24 12:00:00 +1400\n",
        "Date: Mon, 01 Jan 2024 12:00:00 +0000\nDate: Tue, 02 Jan 2024 08:30:00 -0700\n",
        "Date: Mon, 01 Jan 2024\n 12:00:00 +0530\n",
        "Date: not a date\n",
        "Subject: no date\n",
        "Date: Mon, 01 Jan 2024 12:00:00 +0000\nDate: not a date\n",
    ];

    struct Fixture {
        directory: TempDir,
        mailbox: Arc<Mailbox>,
    }

    impl Fixture {
        fn batches(&self, columns: &[Column], batch_size: usize) -> Vec<RecordBatch> {
            let pipeline = Arc::new(Pipeline::new(columns.to_vec(), batch_size));
            pipeline
                .reader(&self.mailbox)
                .collect::<Result<_, _>>()
                .expect("every batch is assembled")
        }

        /// Exports every message through the driver into `parquet_path` and returns the row count.
        fn export_parquet(&self, pipeline: &Arc<Pipeline>) -> u64 {
            Export::new(
                Arc::clone(pipeline),
                Arc::clone(&self.mailbox),
                Destination::File(self.parquet_path()),
            )
            .run(Box::new(ParquetExporter::new(Compression::Zstd)))
            .expect("parquet file is written")
            .messages
        }

        fn parquet_path(&self) -> PathBuf {
            self.directory.path().join("out.parquet")
        }

        fn with(contents: &str) -> Self {
            let directory = tempfile::tempdir().expect("temporary directory is created");
            let path = directory.path().join("inbox.mbox");
            fs::write(&path, contents).expect("fixture mbox is written");
            let mailbox = Arc::new(Mailbox::open(&path).expect("fixture mbox opens"));
            Self { directory, mailbox }
        }

        fn written_batches(&self) -> Vec<RecordBatch> {
            let file = File::open(self.parquet_path()).expect("written parquet file opens");
            ParquetRecordBatchReaderBuilder::try_new(file)
                .expect("parquet footer is readable")
                .build()
                .expect("parquet reader builds")
                .collect::<Result<_, _>>()
                .expect("every parquet batch is decoded")
        }
    }

    fn text_lists(batch: &RecordBatch, column: usize) -> Vec<Vec<String>> {
        batch
            .column(column)
            .as_list::<i32>()
            .iter()
            .map(|list| {
                let values = list.expect("list cells are never null");
                values
                    .as_string::<i32>()
                    .iter()
                    .map(|value| value.expect("list elements are never null").to_owned())
                    .collect()
            })
            .collect()
    }

    fn header_batch(columns: &[Column]) -> (Fixture, RecordBatch) {
        let fixture = Fixture::with(MESSAGES);
        let batch = fixture
            .batches(columns, 8)
            .into_iter()
            .next()
            .expect("two messages fit one batch of eight");
        (fixture, batch)
    }

    #[test]
    fn the_raw_column_holds_each_messages_stored_bytes_as_large_binary() {
        let (fixture, batch) = header_batch(&[Column::Raw]);
        assert_eq!(
            batch.schema().field(0).data_type(),
            &arrow_schema::DataType::LargeBinary,
            "raw uses 64-bit offsets"
        );
        let cells = batch.column(0).as_binary::<i64>();
        assert_eq!(
            batch.num_rows(),
            fixture.mailbox.len(),
            "one cell per message"
        );
        for position in 0..fixture.mailbox.len() {
            assert_eq!(
                Some(cells.value(position)),
                fixture.mailbox.raw(position),
                "raw cell {position} equals Mailbox::raw, separator line included"
            );
        }
    }

    #[test]
    fn the_subject_column_lists_each_subject_in_mailbox_order() {
        let (_fixture, batch) = header_batch(&[Column::Subject]);
        let subjects: Vec<_> = batch
            .column(0)
            .as_string::<i32>()
            .iter()
            .map(|subject| subject.expect("both fixture messages have a subject"))
            .collect();
        assert_eq!(
            subjects,
            vec!["first", "second"],
            "one subject per message, in order"
        );
    }

    #[test]
    fn the_received_column_lists_every_received_header_the_message_api_returns() {
        let (fixture, batch) = header_batch(&[Column::Received]);
        let message = fixture.mailbox.message(0).expect("first message exists");
        let expected: Vec<_> = message.header_values("received").collect();
        assert_eq!(
            expected.len(),
            2,
            "the first fixture message has two Received headers"
        );
        assert_eq!(
            text_lists(&batch, 0)[0],
            expected,
            "column matches Message::header_values"
        );
    }

    #[test]
    fn the_from_column_holds_bare_addresses_without_display_names() {
        let (_fixture, batch) = header_batch(&[Column::From]);
        assert_eq!(
            text_lists(&batch, 0),
            vec![vec!["jane@example.com"], vec!["bob@example.com"]],
            "each sender's display name is dropped, leaving the bare address"
        );
    }

    #[test]
    fn a_raw_header_column_is_empty_for_messages_without_that_header() {
        let (_fixture, batch) = header_batch(&[Column::Header("x-mailer".into())]);
        assert_eq!(
            text_lists(&batch, 0),
            vec![vec!["forged".to_owned()], Vec::new()],
            "only the first message carries X-Mailer"
        );
    }

    #[test]
    fn the_attachment_names_column_lists_names_per_message() {
        let (_fixture, batch) = header_batch(&[Column::AttachmentNames]);
        assert_eq!(
            text_lists(&batch, 0),
            vec![Vec::new(), vec!["x.bin".to_owned()]],
            "only the second message has an attachment"
        );
    }

    #[test]
    fn the_attachment_sha256_column_hashes_the_decoded_attachment_bytes() {
        let (_fixture, batch) = header_batch(&[Column::AttachmentSha256]);
        let digest = Sha256::digest([0_u8, 1, 2])
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .concat();
        assert_eq!(
            text_lists(&batch, 0),
            vec![Vec::new(), vec![digest]],
            "the base64 payload AAEC is hashed after decoding"
        );
    }

    #[test]
    fn the_text_column_holds_the_plain_text_part_of_a_multipart_message() {
        let (_fixture, batch) = header_batch(&[Column::Text]);
        assert_eq!(
            batch.column(0).as_string::<i32>().value(1),
            "hello",
            "the text/plain part of the second message is the body text"
        );
    }

    #[test]
    fn a_parquet_export_reports_one_row_per_message() {
        let fixture = Fixture::with(MESSAGES);
        let pipeline = Arc::new(Pipeline::new(Column::defaults(), 1));
        let rows = fixture.export_parquet(&pipeline);
        assert_eq!(rows, 2, "both fixture messages are counted");
    }

    /// A select of the whole date fixture with the Date and offset columns, one row per message.
    fn date_batch() -> (Fixture, RecordBatch) {
        let contents = DATE_MIX
            .iter()
            .map(|header| format!("From x Mon Jan  1 00:00:00 2024\n{header}\nbody\n"))
            .collect::<Vec<_>>()
            .concat();
        let fixture = Fixture::with(&contents);
        let pipeline = Arc::new(Pipeline::new(
            vec![Column::Date, Column::DateOffsetMinutes],
            DATE_MIX.len(),
        ));
        let batch = pipeline
            .select(&fixture.mailbox, Selection::All)
            .expect("the whole mailbox is selectable")
            .next()
            .expect("one batch covers the fixture")
            .expect("the batch is assembled");
        (fixture, batch)
    }

    fn assert_date_row_agrees(fixture: &Fixture, batch: &RecordBatch, position: usize) {
        let dates = batch.column(0).as_primitive::<TimestampMicrosecondType>();
        let offsets = batch.column(1).as_primitive::<Int32Type>();
        let indexed = fixture
            .mailbox
            .date(position)
            .map(|seconds| seconds.saturating_mul(1_000_000));
        let stamp = fixture
            .mailbox
            .message(position)
            .expect("the position exists")
            .date();
        assert_eq!(
            dates.is_valid(position).then(|| dates.value(position)),
            indexed,
            "message {position}: the Date column matches the index"
        );
        assert_eq!(
            stamp.map(|found| found.unix_seconds.saturating_mul(1_000_000)),
            indexed,
            "message {position}: Message::date matches the index"
        );
        assert_eq!(
            offsets.is_valid(position).then(|| offsets.value(position)),
            stamp.map(|found| found.offset_minutes),
            "message {position}: the offset column matches Message::date"
        );
    }

    #[test]
    fn the_date_column_equals_the_index_date_for_every_message() {
        let (fixture, batch) = date_batch();
        for position in 0..DATE_MIX.len() {
            assert_date_row_agrees(&fixture, &batch, position);
        }
        let dates = batch.column(0).as_primitive::<TimestampMicrosecondType>();
        assert_eq!(
            dates.null_count(),
            3,
            "unparsable, missing and bad-last are null"
        );
        assert!(fixture.mailbox.date(1).is_some(), "asctime is dated");
    }

    #[test]
    fn the_parquet_file_holds_every_subject_the_reader_yields_in_order() {
        let fixture = Fixture::with(MESSAGES);
        let pipeline = Arc::new(Pipeline::new(Column::defaults(), 1));
        let rows = fixture.export_parquet(&pipeline);
        assert_eq!(rows, 2, "the writer reports both messages");
        let subjects: Vec<_> = fixture
            .written_batches()
            .iter()
            .flat_map(|batch| {
                let position = batch
                    .schema()
                    .index_of("subject")
                    .expect("default columns include subject");
                batch
                    .column(position)
                    .as_string::<i32>()
                    .iter()
                    .map(|subject| subject.map(str::to_owned))
                    .collect::<Vec<_>>()
            })
            .collect();
        assert_eq!(
            subjects,
            vec![Some("first".to_owned()), Some("second".to_owned())],
            "the file round-trips both subjects in order"
        );
    }

    fn numbered(count: usize) -> Fixture {
        let contents = (0..count)
            .map(|index| format!("From x Mon Jan  1 00:00:00 2024\nSubject: {index}\n\nb\n"))
            .collect::<Vec<_>>()
            .concat();
        Fixture::with(&contents)
    }

    fn selected(
        fixture: &Fixture,
        selection: &Selection,
        batch_size: usize,
        threads: usize,
    ) -> Vec<usize> {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .expect("thread pool is built");
        let pipeline = Arc::new(Pipeline::new(vec![Column::Position], batch_size));
        pool.install(|| {
            pipeline
                .select(&fixture.mailbox, selection.clone())
                .expect("selection is within the mailbox")
                .map(|batch| batch.expect("every batch is assembled"))
                .flat_map(|batch| {
                    batch
                        .column(0)
                        .as_primitive::<UInt64Type>()
                        .values()
                        .to_vec()
                })
                .map(|position| usize::try_from(position).expect("position fits in usize"))
                .collect()
        })
    }

    #[test]
    fn selections_yield_exactly_their_positions_in_order_at_any_batch_size_and_thread_count() {
        let fixture = numbered(20);
        let ranges = Selection::Ranges(vec![15..18, 2..5, 3..4, 7..7, 0..2]);
        let listed = Selection::Positions(vec![9, 9, 4, 3, 2, 19, 0, 1, 2]);
        for (batch_size, threads) in [(1, 1), (2, 3), (4, 2), (7, 4), (100, 2)] {
            assert_eq!(
                selected(&fixture, &Selection::All, batch_size, threads),
                (0..20).collect::<Vec<_>>(),
                "All yields every message at batch {batch_size}, {threads} threads"
            );
            assert_eq!(
                selected(&fixture, &ranges, batch_size, threads),
                [15, 16, 17, 2, 3, 4, 3, 0, 1],
                "ranges keep their order and repeats at batch {batch_size}, {threads} threads"
            );
            assert_eq!(
                selected(&fixture, &listed, batch_size, threads),
                [9, 9, 4, 3, 2, 19, 0, 1, 2],
                "listed positions keep order and repeats at batch {batch_size}, {threads} threads"
            );
        }
    }

    #[test]
    fn a_reader_reports_the_selection_size_before_reading() {
        let fixture = numbered(10);
        let pipeline = Arc::new(Pipeline::new(vec![Column::Position], 3));
        let total = |selection| {
            pipeline
                .select(&fixture.mailbox, selection)
                .expect("selection is within the mailbox")
                .total()
        };
        assert_eq!(total(Selection::All), 10, "All covers the mailbox");
        assert_eq!(
            total(Selection::Ranges(vec![0..4, 2..3, 5..5])),
            5,
            "range lengths add up"
        );
        assert_eq!(
            total(Selection::Positions(vec![7, 7, 1])),
            3,
            "repeats count"
        );
        assert_eq!(
            pipeline.reader(&fixture.mailbox).total(),
            10,
            "reader() selects all"
        );
    }

    #[test]
    fn a_position_past_the_last_message_is_rejected_naming_it_and_the_length() {
        let fixture = numbered(5);
        let pipeline = Arc::new(Pipeline::new(vec![Column::Position], 2));
        let rejected = |selection| {
            pipeline
                .select(&fixture.mailbox, selection)
                .expect_err("the selection reaches past the mailbox")
        };
        assert!(
            matches!(
                rejected(Selection::Positions(vec![0, 5, 9])),
                MboxTurboError::PositionOutOfRange {
                    position: 5,
                    len: 5
                }
            ),
            "a listed position equal to the length is out of range"
        );
        assert!(
            matches!(
                rejected(Selection::Ranges(vec![0..2, 3..8])),
                MboxTurboError::PositionOutOfRange {
                    position: 5,
                    len: 5
                }
            ),
            "a range ending past the length names the first missing position"
        );
    }

    fn numbered_mailbox(count: usize) -> Fixture {
        let contents = (0..count)
            .map(|index| format!("From x Mon Jan  1 00:00:00 2024\nSubject: s{index}\n\nb\n"))
            .collect::<Vec<_>>()
            .concat();
        Fixture::with(&contents)
    }

    /// The (position, subject) pair of every row of a two-column position and subject batch.
    fn rows(batch: &RecordBatch) -> Vec<(u64, String)> {
        let positions = batch.column(0).as_primitive::<UInt64Type>();
        let subjects = batch.column(1).as_string::<i32>();
        (0..batch.num_rows())
            .map(|row| (positions.value(row), subjects.value(row).to_owned()))
            .collect()
    }

    /// The positions each selection yields, flattened, for a mailbox of `count` messages.
    fn selections(count: usize) -> Vec<(Selection, Vec<usize>)> {
        let positions = vec![count.saturating_sub(1), 3, 3, 0, 7, 8, 9, 2, 1];
        // The last range is reversed on purpose: it selects nothing.
        let ranges = vec![5..12, 0..0, 20..count, 2..4, Range { start: 12, end: 5 }];
        let flat_ranges = ranges.iter().cloned().flatten().collect();
        vec![
            (Selection::All, (0..count).collect()),
            (Selection::Positions(positions.clone()), positions),
            (Selection::Ranges(ranges), flat_ranges),
        ]
    }

    /// The rows of every batch the reader for `selection` yields, read on `pool`.
    fn read_selection(
        pool: &rayon::ThreadPool,
        pipeline: &Arc<Pipeline>,
        fixture: &Fixture,
        selection: Selection,
    ) -> Vec<Vec<(u64, String)>> {
        pool.install(|| {
            pipeline
                .select(&fixture.mailbox, selection)
                .expect("the selection is within the mailbox")
                .map(|batch| rows(&batch.expect("every batch is assembled")))
                .collect()
        })
    }

    /// The rows single-batch extraction gives for `expected` positions, `batch_size` at a time.
    fn extracted_rows(
        pipeline: &Pipeline,
        fixture: &Fixture,
        expected: &[usize],
        batch_size: usize,
    ) -> Vec<Vec<(u64, String)>> {
        expected
            .chunks(batch_size)
            .map(|chunk| {
                chunk
                    .iter()
                    .flat_map(|&position| {
                        rows(
                            &pipeline
                                .extract(&fixture.mailbox, position..position.saturating_add(1))
                                .expect("one message is extracted"),
                        )
                    })
                    .collect()
            })
            .collect()
    }

    /// Asserts that every selection over `fixture` read on `pool` yields the batches single-batch
    /// extraction gives.
    fn assert_batches_match(
        pool: &rayon::ThreadPool,
        fixture: &Fixture,
        columns: &[Column],
        batch_size: usize,
    ) {
        let pipeline = Arc::new(Pipeline::new(columns.to_vec(), batch_size));
        let count = fixture.mailbox.len();
        for (selection, expected) in selections(count) {
            assert_eq!(
                read_selection(pool, &pipeline, fixture, selection),
                extracted_rows(&pipeline, fixture, &expected, batch_size),
                "{} threads, batch size {batch_size}: batches match extraction",
                pool.current_num_threads()
            );
        }
    }

    #[test]
    fn a_reader_yields_the_batches_single_batch_extraction_gives_at_any_threads_and_batch_size() {
        let count = 37;
        let fixture = numbered_mailbox(count);
        let columns = [Column::Position, Column::Subject];
        for threads in [1, 2, 5] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .expect("test thread pool builds");
            for batch_size in [1, 3, 8, 100] {
                assert_batches_match(&pool, &fixture, &columns, batch_size);
            }
        }
    }

    #[test]
    fn dropping_a_reader_part_way_returns_and_leaves_the_pool_usable() {
        let fixture = numbered_mailbox(200);
        let pipeline = Arc::new(Pipeline::new(vec![Column::Subject], 2));
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .expect("test thread pool builds");
        let first = pool.install(|| {
            let mut reader = pipeline.reader(&fixture.mailbox);
            reader
                .next()
                .expect("a batch exists")
                .expect("it is assembled")
        });
        assert_eq!(first.num_rows(), 2, "the first batch holds batch-size rows");
        assert_eq!(
            pool.install(|| 1_i32.saturating_add(1)),
            2_i32,
            "the pool still runs work after the reader was dropped"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn batches_cover_every_row_in_order_at_any_batch_size(
            count in 0_usize..60,
            batch_size in 1_usize..12,
        ) {
            let contents = (0..count)
                .map(|index| format!("From x Mon Jan  1 00:00:00 2024\nSubject: {index}\n\nb\n"))
                .collect::<Vec<_>>()
                .concat();
            let fixture = Fixture::with(&contents);
            let positions: Vec<u64> = fixture
                .batches(&[Column::Position], batch_size)
                .iter()
                .flat_map(|batch| batch.column(0).as_primitive::<UInt64Type>().values().to_vec())
                .collect();
            prop_assert_eq!(
                positions,
                (0..count)
                    .map(|index| u64::try_from(index).expect("index fits in u64"))
                    .collect::<Vec<_>>(),
                "positions are 0..count in order whatever the batch size"
            );
        }
    }
}
