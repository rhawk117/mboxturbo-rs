//! The column pipeline agrees with the `Message` API, keeps every row in order, and round-trips
//! through Parquet.

#[cfg(test)]
mod pipeline {
    use std::fs::{self, File};
    use std::ops::Range;
    use std::path::PathBuf;
    use std::sync::Arc;

    use arrow_array::cast::AsArray as _;
    use arrow_array::types::{
        Int8Type, Int32Type, TimestampMicrosecondType, UInt8Type, UInt64Type,
    };
    use arrow_array::{Array as _, RecordBatch, StructArray};
    use mail_parser::MessageParser;
    use mboxturbo::{
        Column, Compression, Destination, Export, Mailbox, MboxTurboError, ParquetExporter,
        Pipeline, Selection, TrustSet,
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

    const STRUCTURED: &str = "From a@example.com Mon Jan  1 00:00:00 2024\n\
Authentication-Results: evil.example; dmarc=pass header.from=example.org\n\
Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=example.org;\n\
\tdkim=fail reason=\"bad sig\"\n\
Subject: forged above real\n\
\n\
body\n\
\n\
From b@example.com Tue Jan  2 00:00:00 2024\n\
ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.org; s=arc; b=c2VhbA==\n\
ARC-Message-Signature: i=1; a=rsa-sha256; d=example.org; s=arc; h=from; bh=aGFzaA==; b=c2ln\n\
ARC-Authentication-Results: i=1; mx.example.org; spf=pass\n\
DKIM-Signature: v=1; a=rsa-sha256; d=example.org; s=sel; h=from:to; bh=aGFzaA==;\n\
\tb=c2ln; t=1700000000\n\
Subject: signed\n\
\n\
body\n\
\n\
From c@example.com Wed Jan  3 00:00:00 2024\n\
DKIM-Signature: v=1; garbage\n\
Subject: malformed signature\n\
\n\
body\n\
\n\
From d@example.com Thu Jan  4 00:00:00 2024\n\
Subject: none of these headers\n\
\n\
body\n";

    /// Header blocks of messages with varied real-world `Received` forms, newest hop first.
    const RECEIVED_CORPUS: [&str; 13] = [
        "Received: from mail.example.org (mail.example.org [203.0.113.7])\n\
\tby mx.example.com (Postfix) with ESMTPS id 4ABC123\n\
\tfor <a@example.com>; Mon, 2 Nov 2026 10:00:00 +0000 (UTC)\n",
        "Received: from [192.0.2.4] (helo=host.example.net)\n\
\tby mx.example.com with esmtp (Exim 4.96) (envelope-from <s@example.net>)\n\
\tid 1abc-0002-XY for a@example.com; Tue, 03 Nov 2026 11:00:00 +0100\n",
        "Received: from AM6PR01MB1234.eurprd01.prod.exchangelabs.com (2603:10a6:20b::22)\n\
\tby DB8PR01MB5678.eurprd01.prod.exchangelabs.com with Microsoft SMTP Server\n\
\t(version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.1;\n\
\tWed, 4 Nov 2026 12:00:00 +0000\n",
        "Received: by 2002:a17:906:1234:0:0:0:0 with SMTP id b1csp123ejc;\n\
\tThu, 5 Nov 2026 01:00:00 -0800 (PST)\n\
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41])\n\
\tby mx.google.com with SMTPS id abc123 for <a@gmail.com>\n\
\t(Google Transport Security); Thu, 5 Nov 2026 01:00:00 -0800 (PST)\n",
        "Received: (qmail 4242 invoked by uid 1000); 5 Nov 2026 09:00:00 -0000\n",
        "Received: from relay.example.org\n\
\t(relay.example.org\n\
\t[198.51.100.9])\n\
\tby mx.example.com\n\
\twith ESMTP\n\
\tid Z9; Fri, 6 Nov 2026 09:00:00 +0000\n",
        "Received: by mx.example.com (Postfix, from userid 0)\n\
\tid ABC; Sat, 7 Nov 2026 08:00:00 +0000\n",
        "Received: from a.example.org by mx.example.com with SMTP id 1\n",
        "Received: ;;;((( not a received header at all\n",
        "Subject: no received header\n",
        "Received: from mx.example.net (mx.example.net [192.0.2.1])\n\
\t(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits))\n\
\tby mx.example.com (Postfix) with ESMTPS id 1; Sun, 8 Nov 2026 07:00:00 +0000\n",
        "Received: from mx.example.com (mx.example.com [192.0.2.10])\n\
\tby mx2.example.com with ESMTP id 2; Mon, 9 Nov 2026 07:00:03 +0000\n\
Received: from edge.example.org (edge.example.org [198.51.100.5])\n\
\tby mx.example.com with ESMTP id 3; Mon, 9 Nov 2026 07:00:01 +0000\n",
        "Received: from\n",
    ];

    const PARSED_HEADERS: &str = "From a@example.com Mon Jan  1 00:00:00 2024\n\
Received-SPF: pass (example.com: domain of a@example.org designates 192.0.2.1 as permitted\n\
\tsender) client-ip=192.0.2.1; envelope-from=a@example.org;\n\
X-Forefront-Antispam-Report: CIP:192.0.2.1;SCL:5;CAT:SPM;SFV:SPM;\n\
X-Microsoft-Antispam: BCL:3;\n\
Subject: scored\n\
\n\
body\n\
\n\
From b@example.com Tue Jan  2 00:00:00 2024\n\
Subject: none of these headers\n\
\n\
body\n";

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

    /// The corpus as one mailbox, each header block followed by a one-line body.
    fn corpus_mbox() -> String {
        let mut mbox = String::new();
        for headers in RECEIVED_CORPUS {
            mbox.push_str("From x Mon Jan  1 00:00:00 2024\n");
            mbox.push_str(headers);
            mbox.push_str("\nbody\n\n");
        }
        mbox
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

    fn structured_batch(columns: &[Column], trust: Option<TrustSet>) -> RecordBatch {
        let fixture = Fixture::with(STRUCTURED);
        let base = Pipeline::new(columns.to_vec(), 8);
        let pipeline = Arc::new(match trust {
            Some(set) => base.with_trust(set),
            None => base,
        });
        pipeline
            .reader(&fixture.mailbox)
            .next()
            .expect("four messages fit one batch of eight")
            .expect("the structured batch is assembled")
    }

    fn trust_mx() -> TrustSet {
        TrustSet::new().add_authserv_id("mx.example.org").clone()
    }

    /// The elements of row `row` of the list-of-struct column `column`.
    fn elements(batch: &RecordBatch, column: usize, row: usize) -> StructArray {
        batch
            .column(column)
            .as_list::<i32>()
            .value(row)
            .as_struct()
            .clone()
    }

    fn text_field(elements: &StructArray, name: &str) -> Vec<Option<String>> {
        elements
            .column_by_name(name)
            .unwrap_or_else(|| panic!("the element struct has a {name} field"))
            .as_string::<i32>()
            .iter()
            .map(|value| value.map(str::to_owned))
            .collect()
    }

    fn assert_tags(elements: &StructArray, column: &str, expected: &[&str]) {
        let list = elements
            .column_by_name(column)
            .unwrap_or_else(|| panic!("the element struct has a {column} field"))
            .as_list::<i32>()
            .value(0);
        let tags = list.as_struct();
        let pairs: Vec<String> = text_field(tags, "name")
            .into_iter()
            .zip(text_field(tags, "value"))
            .map(|(name, value)| {
                format!(
                    "{}={}",
                    name.expect("a tag has a name"),
                    value.expect("a tag has a value")
                )
            })
            .collect();
        assert_eq!(pairs, expected, "the {column} tag list is exposed");
    }

    fn trusted_flags(elements: &StructArray) -> Vec<Option<bool>> {
        elements
            .column_by_name("trusted")
            .expect("the element struct has a trusted field")
            .as_boolean()
            .iter()
            .collect()
    }

    fn issue_kinds(elements: &StructArray, element: usize) -> Vec<String> {
        let issues = elements
            .column_by_name("issues")
            .expect("the element struct has an issues field")
            .as_list::<i32>()
            .value(element);
        text_field(issues.as_struct(), "kind")
            .into_iter()
            .map(|kind| kind.expect("an issue always has a kind"))
            .collect()
    }

    #[test]
    fn a_forged_topmost_authentication_results_is_untrusted_and_the_real_one_trusted() {
        let batch = structured_batch(&[Column::AuthResults], Some(trust_mx()));
        let first = elements(&batch, 0, 0);
        assert_eq!(
            text_field(&first, "authserv_id"),
            vec![
                Some("evil.example".to_owned()),
                Some("mx.example.org".to_owned())
            ],
            "both headers are listed in header order"
        );
        assert_eq!(
            trusted_flags(&first),
            vec![Some(false), Some(true)],
            "only the authserv-id in the trust set is trusted"
        );
    }

    #[test]
    fn without_a_trust_set_every_trusted_flag_is_null() {
        let batch = structured_batch(&[Column::AuthResults], None);
        assert_eq!(
            trusted_flags(&elements(&batch, 0, 0)),
            vec![None, None],
            "nothing can be said without a trust set"
        );
    }

    /// The `entries` of element `element` of the first message's `auth_results`.
    fn entries_of(batch: &RecordBatch, element: usize) -> StructArray {
        let first = elements(batch, 0, 0);
        let list = first
            .column_by_name("entries")
            .expect("the element struct has an entries field")
            .as_list::<i32>()
            .value(element);
        list.as_struct().clone()
    }

    #[test]
    fn auth_results_entries_carry_method_result_and_reason() {
        let batch = structured_batch(&[Column::AuthResults], None);
        let entries = entries_of(&batch, 1);
        assert_eq!(
            text_field(&entries, "method"),
            vec![Some("spf".to_owned()), Some("dkim".to_owned())],
            "methods are named as written, in order"
        );
        assert_eq!(
            text_field(&entries, "result"),
            vec![Some("pass".to_owned()), Some("fail".to_owned())],
            "results are named as written"
        );
        assert_eq!(
            text_field(&entries, "reason"),
            vec![None, Some("bad sig".to_owned())],
            "a missing reason is null and a quoted one is unquoted"
        );
    }

    #[test]
    fn auth_results_entries_carry_their_properties() {
        let batch = structured_batch(&[Column::AuthResults], None);
        let entries = entries_of(&batch, 1);
        let properties = entries
            .column_by_name("properties")
            .expect("the entry struct has a properties field")
            .as_list::<i32>()
            .value(0);
        assert_eq!(
            text_field(properties.as_struct(), "property"),
            vec![Some("mailfrom".to_owned())],
            "the spf entry has its smtp.mailfrom property"
        );
    }

    #[test]
    fn a_message_without_the_headers_gets_empty_lists_never_null() {
        let batch = structured_batch(
            &[Column::AuthResults, Column::ArcSets, Column::DkimSignatures],
            None,
        );
        for column in [0, 2] {
            let list = batch.column(column).as_list::<i32>();
            assert!(
                list.is_valid(3),
                "column {column} is not null for a bare message"
            );
            assert_eq!(
                list.value(3).len(),
                0,
                "column {column} is empty for a bare message"
            );
        }
    }

    #[test]
    fn a_message_without_arc_headers_gets_an_arc_sets_struct_of_empty_lists() {
        let batch = structured_batch(&[Column::ArcSets], None);
        let arc_sets = batch.column(0).as_struct();
        for name in ["sets", "issues"] {
            let list = arc_sets
                .column_by_name(name)
                .unwrap_or_else(|| panic!("arc_sets has a {name} field"))
                .as_list::<i32>();
            assert!(
                list.is_valid(3),
                "arc_sets.{name} is not null for a bare message"
            );
            assert_eq!(
                list.value(3).len(),
                0,
                "arc_sets.{name} is empty for a bare message"
            );
        }
        assert!(
            arc_sets.is_valid(3),
            "arc_sets is not null for a bare message"
        );
    }

    fn arc_sets_of_second_message() -> StructArray {
        let batch = structured_batch(&[Column::ArcSets], Some(trust_mx()));
        arc_sets_of(&batch, 1)
    }

    /// The sets of message `row` in the `arc_sets` struct column 0.
    fn arc_sets_of(batch: &RecordBatch, row: usize) -> StructArray {
        batch
            .column(0)
            .as_struct()
            .column_by_name("sets")
            .expect("arc_sets has a sets field")
            .as_list::<i32>()
            .value(row)
            .as_struct()
            .clone()
    }

    /// The chain-level issue kinds of message `row` in the `arc_sets` struct column 0.
    fn arc_chain_issue_kinds(batch: &RecordBatch, row: usize) -> Vec<String> {
        let issues = batch
            .column(0)
            .as_struct()
            .column_by_name("issues")
            .expect("arc_sets has an issues field")
            .as_list::<i32>()
            .value(row);
        text_field(issues.as_struct(), "kind")
            .into_iter()
            .map(|kind| kind.expect("an issue always has a kind"))
            .collect()
    }

    #[test]
    fn three_arc_headers_of_one_instance_form_one_set_with_its_seal() {
        let batch = structured_batch(&[Column::ArcSets], Some(trust_mx()));
        let sets = arc_sets_of(&batch, 1);
        assert_eq!(sets.len(), 1, "the three ARC headers form one set");
        let instances = sets
            .column_by_name("instance")
            .expect("the element struct has an instance field")
            .as_primitive::<UInt8Type>()
            .values()
            .to_vec();
        assert_eq!(instances, vec![1_u8], "the set is instance 1");
        assert_eq!(
            text_field(&sets, "chain_validation"),
            vec![Some("none".to_owned())],
            "the seal's cv tag is exposed"
        );
        assert!(
            arc_chain_issue_kinds(&batch, 1).is_empty(),
            "a complete ARC set has no issues"
        );
    }

    #[test]
    fn an_arc_chain_problem_that_names_no_instance_is_reported_in_arc_sets_issues() {
        let fixture = Fixture::with(
            "From a@example.com Mon Jan  1 00:00:00 2024\n\
ARC-Seal: a=rsa-sha256; cv=none; d=example.org; s=arc; b=c2VhbA==\n\
Subject: seal without an instance\n\
\n\
body\n",
        );
        let batches = fixture.batches(&[Column::ArcSets], 8);
        let batch = batches.first().expect("one batch holds the message");
        assert_eq!(
            arc_sets_of(batch, 0).len(),
            0,
            "the seal without an instance forms no set"
        );
        assert!(
            !arc_chain_issue_kinds(batch, 0).is_empty(),
            "the dropped header is reported at the chain level"
        );
    }

    #[test]
    fn an_arc_sets_seal_and_message_signature_expose_their_tag_lists_in_header_order() {
        let sets = arc_sets_of_second_message();
        assert_tags(
            &sets,
            "seal",
            &[
                "i=1",
                "a=rsa-sha256",
                "cv=none",
                "d=example.org",
                "s=arc",
                "b=c2VhbA==",
            ],
        );
        assert_tags(
            &sets,
            "message_signature",
            &[
                "i=1",
                "a=rsa-sha256",
                "d=example.org",
                "s=arc",
                "h=from",
                "bh=aGFzaA==",
                "b=c2ln",
            ],
        );
    }

    #[test]
    fn an_arc_sets_authentication_results_are_judged_by_the_trust_set() {
        let sets = arc_sets_of_second_message();
        let results = sets
            .column_by_name("authentication_results")
            .expect("the element struct has an authentication_results field")
            .as_struct();
        assert_eq!(
            text_field(results, "authserv_id"),
            vec![Some("mx.example.org".to_owned())],
            "the ARC AR carries its authserv-id"
        );
        assert_eq!(
            trusted_flags(results),
            vec![Some(true)],
            "the ARC AR is trusted"
        );
    }

    #[test]
    fn one_dkim_signature_yields_one_element_with_its_tags_and_no_issues() {
        let batch = structured_batch(&[Column::DkimSignatures], None);
        let signatures = elements(&batch, 0, 1);
        assert_eq!(signatures.len(), 1, "one DKIM-Signature header");
        assert_eq!(
            text_field(&signatures, "domain"),
            vec![Some("example.org".to_owned())],
            "the d tag is exposed"
        );
        let other = signatures
            .column_by_name("tags")
            .expect("the element struct has a tags field")
            .as_list::<i32>()
            .value(0);
        assert_eq!(
            text_field(other.as_struct(), "name"),
            vec![Some("t".to_owned())],
            "only the tags without a column of their own are listed"
        );
        assert!(
            issue_kinds(&signatures, 0).is_empty(),
            "a well-formed signature, folded over two lines, has no issues"
        );
    }

    #[test]
    fn a_malformed_dkim_signature_yields_an_element_with_issues() {
        let batch = structured_batch(&[Column::DkimSignatures], None);
        let signatures = elements(&batch, 0, 2);
        assert_eq!(
            signatures.len(),
            1,
            "the malformed header still yields an element"
        );
        let kinds = issue_kinds(&signatures, 0);
        assert!(
            kinds.contains(&"missing_tag".to_owned()),
            "the absent required tags are reported by name: {kinds:?}"
        );
    }

    #[test]
    fn structured_columns_round_trip_through_parquet() {
        let fixture = Fixture::with(STRUCTURED);
        let pipeline = Arc::new(
            Pipeline::new(
                vec![
                    Column::AuthResults,
                    Column::ArcSets,
                    Column::DkimSignatures,
                    Column::ReceivedHops,
                    Column::ReceivedSpfParsed,
                    Column::MicrosoftAntispam,
                ],
                2,
            )
            .with_trust(trust_mx()),
        );
        assert_eq!(
            fixture.export_parquet(&pipeline),
            4,
            "every message is written"
        );
        let rows: usize = fixture
            .written_batches()
            .iter()
            .map(RecordBatch::num_rows)
            .sum();
        assert_eq!(
            rows, 4,
            "the nested columns are read back for every message"
        );
    }

    fn received_hops_batch(trust: Option<TrustSet>) -> RecordBatch {
        let fixture = Fixture::with(&corpus_mbox());
        let base = Pipeline::new(vec![Column::ReceivedHops], 16);
        let pipeline = Arc::new(match trust {
            Some(set) => base.with_trust(set),
            None => base,
        });
        pipeline
            .reader(&fixture.mailbox)
            .next()
            .expect("thirteen messages fit one batch of sixteen")
            .expect("the received_hops batch is assembled")
    }

    /// The hops of message `row` in the `received_hops` struct column 0.
    fn hops_of(batch: &RecordBatch, row: usize) -> StructArray {
        batch
            .column(0)
            .as_struct()
            .column_by_name("hops")
            .expect("received_hops has a hops field")
            .as_list::<i32>()
            .value(row)
            .as_struct()
            .clone()
    }

    #[test]
    fn received_hops_finds_a_hop_wherever_mail_parser_finds_a_host() {
        let batch = received_hops_batch(None);
        let ours = (0..RECEIVED_CORPUS.len())
            .filter(|row| !hops_of(&batch, *row).is_empty())
            .count();
        let theirs = RECEIVED_CORPUS
            .iter()
            .filter(|headers| {
                let text = format!("{headers}\nbody\n");
                MessageParser::new()
                    .parse(text.as_bytes())
                    .is_some_and(|message| {
                        message
                            .all_received()
                            .any(|hop| hop.from().is_some() || hop.by().is_some())
                    })
            })
            .count();
        assert!(
            theirs >= 8,
            "mail-parser reads the varied corpus ({theirs} messages)"
        );
        assert!(
            ours >= theirs,
            "received_hops has a hop for {ours} messages, mail-parser a host for {theirs}"
        );
    }

    #[test]
    fn received_hops_exposes_the_microsoft_tls_details() {
        let batch = received_hops_batch(None);
        let exchange = hops_of(&batch, 2);
        let tls = exchange
            .column_by_name("tls")
            .expect("a hop has a tls field")
            .as_struct();
        assert_eq!(
            text_field(tls, "version"),
            [Some("TLS1_2".to_owned())],
            "the Microsoft TLS version is exposed"
        );
        assert_eq!(
            text_field(tls, "cipher"),
            [Some("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_owned())],
            "the Microsoft cipher is exposed"
        );
    }

    #[test]
    fn received_hops_dates_are_utc_microseconds_and_null_when_missing() {
        let batch = received_hops_batch(None);
        let exchange = hops_of(&batch, 2);
        let dates = exchange
            .column_by_name("date")
            .expect("a hop has a date field")
            .as_primitive::<TimestampMicrosecondType>();
        assert_eq!(
            dates.value(0),
            1_793_793_600_000_000,
            "the hop date is UTC microseconds"
        );
        let undated = hops_of(&batch, 7);
        assert!(
            undated
                .column_by_name("date")
                .expect("a hop has a date field")
                .is_null(0),
            "a hop without a date has a null date"
        );
    }

    #[test]
    fn a_message_without_received_headers_gets_empty_hops_never_null() {
        let batch = received_hops_batch(None);
        assert!(
            batch.column(0).as_struct().is_valid(9) && hops_of(&batch, 9).is_empty(),
            "a message without Received headers gets an empty hops list, not null"
        );
    }

    /// The `first_external` flags of `hops`, null without a trust set.
    fn first_external_flags(hops: &StructArray) -> Vec<Option<bool>> {
        hops.column_by_name("first_external")
            .expect("a hop has a first_external field")
            .as_boolean()
            .iter()
            .collect()
    }

    #[test]
    fn first_external_is_true_on_exactly_the_hop_from_outside_the_trust_set() {
        let trust = TrustSet::new()
            .add_host("mx.example.com")
            .add_host("mx2.example.com")
            .clone();
        let chain = hops_of(&received_hops_batch(Some(trust)), 11);
        assert_eq!(
            text_field(&chain, "from_host"),
            [
                Some("edge.example.org".to_owned()),
                Some("mx.example.com".to_owned())
            ],
            "the hops are oldest first"
        );
        assert_eq!(
            first_external_flags(&chain),
            [Some(true), Some(false)],
            "only the hop received from outside the trust set is first_external"
        );
    }

    #[test]
    fn first_external_is_null_without_a_trust_set() {
        let chain = hops_of(&received_hops_batch(None), 11);
        assert_eq!(
            first_external_flags(&chain),
            [None, None],
            "first_external is null on every hop without a trust set"
        );
    }

    fn parsed_headers_batch() -> RecordBatch {
        Fixture::with(PARSED_HEADERS)
            .batches(&[Column::ReceivedSpfParsed, Column::MicrosoftAntispam], 8)
            .into_iter()
            .next()
            .expect("two messages fit one batch of eight")
    }

    #[test]
    fn received_spf_parsed_exposes_the_verdict_and_client_address() {
        let spf = elements(&parsed_headers_batch(), 0, 0);
        assert_eq!(
            text_field(&spf, "result"),
            [Some("pass".to_owned())],
            "the SPF verdict is exposed"
        );
        assert_eq!(
            text_field(&spf, "client_ip"),
            [Some("192.0.2.1".to_owned())],
            "the SPF client address is exposed"
        );
    }

    #[test]
    fn microsoft_antispam_gives_an_element_per_header_in_header_order() {
        let antispam = elements(&parsed_headers_batch(), 1, 0);
        assert_eq!(
            text_field(&antispam, "header"),
            [
                Some("x-forefront-antispam-report".to_owned()),
                Some("x-microsoft-antispam".to_owned())
            ],
            "both Microsoft headers give an element, in header order"
        );
        assert_eq!(
            antispam
                .column_by_name("scl")
                .expect("an element has an scl field")
                .as_primitive::<Int8Type>()
                .iter()
                .collect::<Vec<_>>(),
            [Some(5), None],
            "SCL is read from the header that has it"
        );
    }

    #[test]
    fn a_message_without_the_parsed_headers_gets_empty_lists_never_null() {
        let batch = parsed_headers_batch();
        for column in [0, 1] {
            let list = batch.column(column).as_list::<i32>();
            assert!(
                list.is_valid(1),
                "column {column} is not null for a bare message"
            );
            assert_eq!(
                list.value(1).len(),
                0,
                "column {column} is empty for a bare message"
            );
        }
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
