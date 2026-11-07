//! The column pipeline agrees with the `Message` API, keeps every row in order, and round-trips
//! through Parquet.

#[cfg(test)]
mod pipeline {
    use std::fs::{self, File};
    use std::path::PathBuf;
    use std::sync::Arc;

    use arrow_array::RecordBatch;
    use arrow_array::cast::AsArray;
    use arrow_array::types::UInt64Type;
    use mboxturbo::{Column, Compression, Mailbox, Pipeline};
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use proptest::prelude::*;
    use sha2::{Digest, Sha256};
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
            let directory = tempfile::tempdir().expect("tempdir");
            let path = directory.path().join("inbox.mbox");
            fs::write(&path, contents).expect("write mbox");
            let mailbox = Arc::new(Mailbox::open(&path).expect("open"));
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
                .expect("batches")
        }
    }

    fn text_lists(batch: &RecordBatch, column: usize) -> Vec<Vec<String>> {
        batch
            .column(column)
            .as_list::<i32>()
            .iter()
            .map(|list| {
                let values = list.expect("list");
                values
                    .as_string::<i32>()
                    .iter()
                    .map(|v| v.unwrap_or_default().to_owned())
                    .collect()
            })
            .collect()
    }

    #[test]
    fn header_columns_match_the_message_api() {
        let fixture = Fixture::with(MESSAGES);
        let columns = [
            Column::Subject,
            Column::Received,
            Column::From,
            Column::Header("x-mailer".into()),
        ];
        let batch = &fixture.batches(&columns, 8)[0];
        let subjects: Vec<_> = batch
            .column(0)
            .as_string::<i32>()
            .iter()
            .map(Option::unwrap)
            .collect();
        let message = fixture.mailbox.message(0).expect("first");
        assert_eq!(subjects, vec!["first", "second"], "subjects");
        assert_eq!(
            text_lists(batch, 1)[0],
            message.header_values("received").collect::<Vec<_>>(),
            "received"
        );
        assert_eq!(
            text_lists(batch, 2),
            vec![vec!["jane@example.com"], vec!["bob@example.com"]],
            "from"
        );
        assert_eq!(
            text_lists(batch, 3),
            vec![vec!["forged".to_owned()], Vec::new()],
            "raw header"
        );
    }

    #[test]
    fn attachment_columns_match_the_message_api() {
        let fixture = Fixture::with(MESSAGES);
        let columns = [
            Column::AttachmentNames,
            Column::AttachmentSha256,
            Column::Text,
        ];
        let batch = &fixture.batches(&columns, 8)[0];
        let digest = Sha256::digest([0_u8, 1, 2])
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .concat();
        assert_eq!(
            text_lists(batch, 0),
            vec![Vec::new(), vec!["x.bin".to_owned()]],
            "names"
        );
        assert_eq!(
            text_lists(batch, 1),
            vec![Vec::new(), vec![digest]],
            "sha256"
        );
        assert_eq!(
            batch.column(2).as_string::<i32>().value(1),
            "hello",
            "text body"
        );
    }

    #[test]
    fn parquet_holds_every_row_the_reader_yields() {
        let fixture = Fixture::with(MESSAGES);
        let pipeline = Arc::new(Pipeline::new(Column::defaults(), 1));
        let rows = pipeline
            .write_parquet(&fixture.mailbox, &fixture.parquet_path(), Compression::Zstd)
            .expect("write");
        let file = File::open(fixture.parquet_path()).expect("open parquet");
        let written: Vec<RecordBatch> = ParquetRecordBatchReaderBuilder::try_new(file)
            .expect("parquet reader")
            .build()
            .expect("build")
            .collect::<Result<_, _>>()
            .expect("read");
        let subjects: Vec<_> = written
            .iter()
            .flat_map(|batch| {
                let position = batch.schema().index_of("subject").expect("subject column");
                batch
                    .column(position)
                    .as_string::<i32>()
                    .iter()
                    .map(|s| s.map(str::to_owned))
                    .collect::<Vec<_>>()
            })
            .collect();
        assert_eq!(rows, 2, "row count");
        assert_eq!(
            subjects,
            vec![Some("first".to_owned()), Some("second".to_owned())],
            "subjects"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn batches_cover_every_row_in_order_at_any_batch_size(count in 0_usize..60, batch_size in 1_usize..12) {
            let contents = (0..count).map(|n| format!("From x Mon Jan  1 00:00:00 2024\nSubject: {n}\n\nb\n")).collect::<Vec<_>>().concat();
            let fixture = Fixture::with(&contents);
            let positions: Vec<u64> = fixture
                .batches(&[Column::Position], batch_size)
                .iter()
                .flat_map(|batch| batch.column(0).as_primitive::<UInt64Type>().values().to_vec())
                .collect();
            prop_assert_eq!(positions, (0..count).map(|n| u64::try_from(n).unwrap()).collect::<Vec<_>>());
        }
    }
}
