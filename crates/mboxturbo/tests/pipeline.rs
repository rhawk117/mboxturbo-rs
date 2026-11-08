//! The column pipeline agrees with the `Message` API, keeps every row in order, and round-trips
//! through Parquet.

#[cfg(test)]
mod pipeline {
    use std::fs::{self, File};
    use std::path::PathBuf;
    use std::sync::Arc;

    use arrow_array::RecordBatch;
    use arrow_array::cast::AsArray as _;
    use arrow_array::types::UInt64Type;
    use mboxturbo::{Column, Compression, Mailbox, Pipeline};
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

    struct Fixture {
        directory: TempDir,
        mailbox: Arc<Mailbox>,
    }

    impl Fixture {
        fn with(contents: &str) -> Self {
            let directory = tempfile::tempdir().expect("temporary directory is created");
            let path = directory.path().join("inbox.mbox");
            fs::write(&path, contents).expect("fixture mbox is written");
            let mailbox = Arc::new(Mailbox::open(&path).expect("fixture mbox opens"));
            Self { directory, mailbox }
        }

        fn parquet_path(&self) -> PathBuf {
            self.directory.path().join("out.parquet")
        }

        fn batches(&self, columns: &[Column], batch_size: usize) -> Vec<RecordBatch> {
            let pipeline = Arc::new(Pipeline::new(columns.to_vec(), batch_size));
            pipeline
                .reader(&self.mailbox)
                .collect::<Result<_, _>>()
                .expect("every batch is assembled")
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
            "the display name of the first sender is dropped"
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
    fn write_parquet_reports_one_row_per_message() {
        let fixture = Fixture::with(MESSAGES);
        let pipeline = Arc::new(Pipeline::new(Column::defaults(), 1));
        let rows = pipeline
            .write_parquet(&fixture.mailbox, &fixture.parquet_path(), Compression::Zstd)
            .expect("parquet file is written");
        assert_eq!(rows, 2, "both fixture messages are counted");
    }

    #[test]
    fn the_parquet_file_holds_every_subject_the_reader_yields_in_order() {
        let fixture = Fixture::with(MESSAGES);
        let pipeline = Arc::new(Pipeline::new(Column::defaults(), 1));
        let rows = pipeline
            .write_parquet(&fixture.mailbox, &fixture.parquet_path(), Compression::Zstd)
            .expect("parquet file is written");
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
