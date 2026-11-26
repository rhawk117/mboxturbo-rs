//! The Arrow IPC sink writes a stream that reads back to the batches of a select of the same
//! columns and positions, and leaves nothing behind when an export stops early.

#[cfg(test)]
mod export_ipc {
    use std::io::Cursor;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::{fs, io};

    use arrow_array::RecordBatch;
    use arrow_ipc::reader::StreamReader;
    use arrow_schema::SchemaRef;
    use mboxturbo::{
        CancelToken, Column, Destination, Export, Exporter, IpcExporter, Mailbox, MboxTurboError,
        Pipeline, Selection, Staged,
    };
    use tempfile::TempDir;

    const BATCH_SIZE: usize = 2;
    const MAILBOX: &[u8] = concat!(
        "From a@example.com Mon Jan  1 00:00:00 2024\n",
        "Subject: zero\n",
        "Date: Mon, 1 Jan 2024 08:00:00 +0000\n",
        "To: x@example.com, y@example.com\n\nbody zero\n\n",
        "From b@example.com Mon Jan  1 00:00:00 2024\n",
        "Subject: one \"quoted\"\n\nno date here\n\n",
        "From c@example.com Mon Jan  1 00:00:00 2024\n",
        "Subject: two\n",
        "Date: Mon, 1 Jan 2024 09:30:15 +0100\n",
        "MIME-Version: 1.0\n",
        "Content-Type: multipart/mixed; boundary=\"b\"\n\n",
        "--b\nContent-Type: text/plain\n\nbody two\n",
        "--b\nContent-Type: application/pdf; name=\"a.pdf\"\n",
        "Content-Disposition: attachment; filename=\"a.pdf\"\n\n",
        "pdfbytes\n--b--\n\n",
        "From d@example.com Mon Jan  1 00:00:00 2024\n",
        "Subject: three\nTo: z@example.com\n\nno final newline",
    )
    .as_bytes();

    /// Delegates to another sink until `batches` have been written, then fails.
    struct FailAfter {
        batches: usize,
        inner: IpcExporter,
    }

    impl Exporter for FailAfter {
        fn accepts(&self, kind: mboxturbo::DestinationKind) -> bool {
            self.inner.accepts(kind)
        }

        fn begin(&mut self, schema: &SchemaRef, staged: &mut Staged) -> Result<(), MboxTurboError> {
            self.inner.begin(schema, staged)
        }

        fn finish(&mut self, staged: &mut Staged) -> Result<u64, MboxTurboError> {
            self.inner.finish(staged)
        }

        fn write(
            &mut self,
            batch: &RecordBatch,
            staged: &mut Staged,
        ) -> Result<u64, MboxTurboError> {
            if self.batches == 0 {
                return Err(MboxTurboError::Io {
                    path: PathBuf::from("sink"),
                    source: io::Error::other("injected sink failure"),
                });
            }
            self.batches = self.batches.saturating_sub(1);
            self.inner.write(batch, staged)
        }
    }

    struct Fixture {
        _input: TempDir,
        mailbox: Arc<Mailbox>,
        output: TempDir,
    }

    impl Fixture {
        fn export(&self, columns: Vec<Column>, destination: Destination) -> Export {
            Export::new(
                Arc::new(Pipeline::new(columns, BATCH_SIZE)),
                Arc::clone(&self.mailbox),
                destination,
            )
        }

        fn leftovers(&self) -> Vec<String> {
            fs::read_dir(self.output.path())
                .expect("output directory is readable")
                .map(|entry| {
                    entry
                        .expect("entry is readable")
                        .file_name()
                        .to_string_lossy()
                        .into_owned()
                })
                .collect()
        }

        fn new() -> Self {
            let input = tempfile::tempdir().expect("input directory creates");
            let path = input.path().join("inbox.mbox");
            fs::write(&path, MAILBOX).expect("fixture mbox is written");
            Self {
                mailbox: Arc::new(Mailbox::open(&path).expect("fixture mbox opens")),
                _input: input,
                output: tempfile::tempdir().expect("output directory creates"),
            }
        }

        fn target(&self) -> PathBuf {
            self.output.path().join("exported.arrows")
        }
    }

    fn all_columns() -> Vec<Column> {
        vec![
            Column::Position,
            Column::Subject,
            Column::Date,
            Column::To,
            Column::AttachmentNames,
            Column::DateOffsetMinutes,
            Column::Raw,
        ]
    }

    fn selected(fixture: &Fixture, columns: &[Column], positions: Vec<usize>) -> Vec<RecordBatch> {
        Arc::new(Pipeline::new(columns.to_vec(), BATCH_SIZE))
            .select(&fixture.mailbox, Selection::Positions(positions))
            .expect("the selection is in range")
            .map(|batch| batch.expect("the batch extracts"))
            .collect()
    }

    fn read_stream(bytes: Vec<u8>) -> (SchemaRef, Vec<RecordBatch>) {
        let reader = StreamReader::try_new(Cursor::new(bytes), None).expect("the stream opens");
        let schema = reader.schema();
        let batches = reader
            .map(|batch| batch.expect("the batch reads back"))
            .collect();
        (schema, batches)
    }

    #[test]
    fn the_file_reads_back_to_the_batches_of_a_select_of_the_same_columns_and_positions() {
        let fixture = Fixture::new();
        let positions = vec![2, 1, 0, 3];
        drop(
            fixture
                .export(all_columns(), Destination::File(fixture.target()))
                .selection(Selection::Positions(positions.clone()))
                .run(Box::new(IpcExporter::new()))
                .expect("the export succeeds"),
        );

        let (schema, batches) =
            read_stream(fs::read(fixture.target()).expect("the target is readable"));
        let expected = selected(&fixture, &all_columns(), positions);
        let expected_schema = expected
            .first()
            .expect("the select yields batches")
            .schema();
        assert_eq!(
            schema, expected_schema,
            "the stream carries the select schema"
        );
        assert_eq!(batches, expected, "the stream holds the selected rows");
    }

    #[test]
    fn a_stream_destination_receives_the_same_bytes_as_a_file() {
        let fixture = Fixture::new();
        let file_target = fixture.target();
        drop(
            fixture
                .export(all_columns(), Destination::File(file_target.clone()))
                .run(Box::new(IpcExporter::new()))
                .expect("the file export succeeds"),
        );
        let stream_target = fixture.output.path().join("stream.arrows");
        let stream = fs::File::create(&stream_target).expect("the stream file is created");
        drop(
            fixture
                .export(all_columns(), Destination::Stream(Box::new(stream)))
                .run(Box::new(IpcExporter::new()))
                .expect("the stream export succeeds"),
        );

        assert_eq!(
            fs::read(&stream_target).expect("the stream file is readable"),
            fs::read(&file_target).expect("the file is readable"),
            "both destinations hold the same stream"
        );
    }

    #[test]
    fn the_output_is_the_stream_format_not_the_file_format() {
        let fixture = Fixture::new();
        drop(
            fixture
                .export(all_columns(), Destination::File(fixture.target()))
                .run(Box::new(IpcExporter::new()))
                .expect("the export succeeds"),
        );
        let bytes = fs::read(fixture.target()).expect("the target is readable");

        assert_ne!(
            bytes.get(..6),
            Some(b"ARROW1".as_slice()),
            "the file-format magic is absent"
        );
        assert_eq!(
            bytes.get(bytes.len().saturating_sub(8)..),
            Some([0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0].as_slice()),
            "the stream ends with the end-of-stream marker"
        );
    }

    #[test]
    fn a_directory_destination_is_refused() {
        let fixture = Fixture::new();
        let error = fixture
            .export(all_columns(), Destination::Directory(fixture.target()))
            .run(Box::new(IpcExporter::new()))
            .expect_err("the sink refuses a directory");

        assert!(
            matches!(error, MboxTurboError::UnsupportedDestination { .. }),
            "the refusal is an unsupported destination error"
        );
        assert!(!fixture.target().exists(), "nothing was written");
    }

    #[test]
    fn cancelling_leaves_nothing_at_the_target() {
        let fixture = Fixture::new();
        let token = CancelToken::new();
        let hook_token = token.clone();
        let error = fixture
            .export(all_columns(), Destination::File(fixture.target()))
            .cancel_token(token)
            .on_progress(move |_progress| hook_token.cancel())
            .run(Box::new(IpcExporter::new()))
            .expect_err("the export is cancelled");

        assert!(
            matches!(error, MboxTurboError::Cancelled { .. }),
            "cancellation is its own error"
        );
        assert!(
            fixture.leftovers().is_empty(),
            "nothing is left at or beside the target"
        );
    }

    #[test]
    fn a_failure_part_way_leaves_nothing_at_the_target() {
        let fixture = Fixture::new();
        let error = fixture
            .export(all_columns(), Destination::File(fixture.target()))
            .run(Box::new(FailAfter {
                batches: 1,
                inner: IpcExporter::new(),
            }))
            .expect_err("the sink fails on its second batch");

        assert!(
            matches!(&error, MboxTurboError::Io { path, .. } if path.as_os_str() == "sink"),
            "the sink's own error is returned"
        );
        assert!(
            fixture.leftovers().is_empty(),
            "nothing is left at or beside the target"
        );
    }
}
