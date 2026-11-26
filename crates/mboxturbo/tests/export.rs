//! The export driver runs any `Exporter` against any destination it accepts, and leaves
//! nothing behind when the export is cancelled or a sink fails.

#[cfg(test)]
mod export {
    use std::fmt::Write as _;
    use std::fs::{self, File};
    use std::io::{self, Write};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::thread;

    use arrow_array::RecordBatch;
    use arrow_array::cast::AsArray as _;
    use arrow_schema::SchemaRef;
    use mboxturbo::{
        CancelToken, Column, Compression, Destination, DestinationKind, Export, Exporter, Mailbox,
        MboxTurboError, Output, Overwrite, ParquetExporter, Pipeline, Progress, Selection, Staged,
    };
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use tempfile::TempDir;

    const MESSAGES: usize = 7;
    const BATCH_SIZE: usize = 2;

    type Case = (fn(PathBuf) -> Destination, Box<dyn Exporter>);

    /// Writes one `NNNN.eml` file per message, from the raw column.
    struct DirectorySink {
        written: usize,
    }

    impl Exporter for DirectorySink {
        fn accepts(&self, kind: DestinationKind) -> bool {
            kind == DestinationKind::Directory
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
            batch: &RecordBatch,
            staged: &mut Staged,
        ) -> Result<u64, MboxTurboError> {
            let Output::Directory(directory) = staged.output() else {
                return Err(staged.unsupported());
            };
            let mut bytes = 0_u64;
            for raw in batch.column(0).as_binary::<i64>().iter().flatten() {
                let path = directory.join(format!("{:04}.eml", self.written));
                fs::write(&path, raw).map_err(|source| MboxTurboError::Io { path, source })?;
                self.written = self.written.saturating_add(1);
                bytes = bytes.saturating_add(count(raw.len()));
            }
            Ok(bytes)
        }
    }

    /// Concatenates the raw column into the staged file or stream.
    struct StreamSink;

    impl Exporter for StreamSink {
        fn accepts(&self, kind: DestinationKind) -> bool {
            kind != DestinationKind::Directory
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
            batch: &RecordBatch,
            staged: &mut Staged,
        ) -> Result<u64, MboxTurboError> {
            let target = staged.target_label().to_path_buf();
            let Output::Writer(writer) = staged.output() else {
                return Err(staged.unsupported());
            };
            let mut bytes = 0_u64;
            for raw in batch.column(0).as_binary::<i64>().iter().flatten() {
                writer.write_all(raw).map_err(|source| MboxTurboError::Io {
                    path: target.clone(),
                    source,
                })?;
                bytes = bytes.saturating_add(count(raw.len()));
            }
            Ok(bytes)
        }
    }

    /// Delegates to another sink until `batches` have been written, then fails.
    struct FailAfter {
        batches: usize,
        inner: Box<dyn Exporter>,
    }

    impl Exporter for FailAfter {
        fn accepts(&self, kind: DestinationKind) -> bool {
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

    /// Delegates to another sink, but fails when it finishes.
    struct FailFinish {
        inner: Box<dyn Exporter>,
    }

    impl Exporter for FailFinish {
        fn accepts(&self, kind: DestinationKind) -> bool {
            self.inner.accepts(kind)
        }

        fn begin(&mut self, schema: &SchemaRef, staged: &mut Staged) -> Result<(), MboxTurboError> {
            self.inner.begin(schema, staged)
        }

        fn finish(&mut self, _staged: &mut Staged) -> Result<u64, MboxTurboError> {
            Err(MboxTurboError::Io {
                path: PathBuf::from("finish"),
                source: io::Error::other("injected finish failure"),
            })
        }

        fn write(
            &mut self,
            batch: &RecordBatch,
            staged: &mut Staged,
        ) -> Result<u64, MboxTurboError> {
            self.inner.write(batch, staged)
        }
    }

    /// A writer whose bytes the test can read after the export has consumed it.
    #[derive(Clone)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedBuffer {
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .map_err(|poisoned| io::Error::other(poisoned.to_string()))?
                .extend_from_slice(buf);
            Ok(buf.len())
        }
    }

    struct Fixture {
        _input: TempDir,
        mailbox: Arc<Mailbox>,
        output: TempDir,
        pipeline: Arc<Pipeline>,
    }

    impl Fixture {
        fn export(&self, destination: Destination) -> Export {
            Export::new(
                Arc::clone(&self.pipeline),
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
            let mut contents = String::new();
            for position in 0..MESSAGES {
                write!(
                    contents,
                    "From a@example.com Mon Jan  1 00:00:00 2024\nSubject: message {position}\n\n\
                     body {position}\n\n"
                )
                .expect("a string accepts formatted text");
            }
            let path = input.path().join("inbox.mbox");
            fs::write(&path, contents).expect("fixture mbox is written");
            Self {
                mailbox: Arc::new(Mailbox::open(&path).expect("fixture mbox opens")),
                _input: input,
                output: tempfile::tempdir().expect("output directory creates"),
                pipeline: Arc::new(Pipeline::new(vec![Column::Raw], BATCH_SIZE)),
            }
        }

        fn raw_messages(&self) -> Vec<Vec<u8>> {
            (0..MESSAGES)
                .map(|position| {
                    self.mailbox
                        .raw(position)
                        .expect("the message exists at that position")
                        .to_vec()
                })
                .collect()
        }

        fn target(&self) -> PathBuf {
            self.output.path().join("target")
        }
    }

    #[test]
    fn a_directory_sink_writes_one_file_per_message_from_the_raw_column() {
        let fixture = Fixture::new();
        let summary = fixture
            .export(Destination::Directory(fixture.target()))
            .run(Box::new(DirectorySink { written: 0 }))
            .expect("the export succeeds");

        let raw = fixture.raw_messages();
        for (position, expected) in raw.iter().enumerate() {
            let written = fs::read(fixture.target().join(format!("{position:04}.eml")))
                .expect("every message has a file");
            assert_eq!(&written, expected, "message {position} is written verbatim");
        }
        assert_eq!(summary.messages, count(MESSAGES), "all counted");
        assert_eq!(
            summary.bytes,
            raw.iter().map(|message| count(message.len())).sum::<u64>(),
            "the sink's byte counts are summed"
        );
        assert_eq!(summary.path, Some(fixture.target()), "path reported");
        assert_eq!(fixture.leftovers(), ["target"], "only the target remains");
    }

    #[test]
    fn a_stream_sink_ends_equal_to_the_selection_in_order() {
        let fixture = Fixture::new();
        let buffer = SharedBuffer(Arc::default());
        let positions = vec![5, 0, 3, 3, 6];
        let summary = fixture
            .export(Destination::Stream(Box::new(buffer.clone())))
            .selection(Selection::Positions(positions.clone()))
            .run(Box::new(StreamSink))
            .expect("the export succeeds");

        let raw = fixture.raw_messages();
        let expected: Vec<u8> = positions
            .iter()
            .flat_map(|position| raw[*position].clone())
            .collect();
        assert_eq!(
            *buffer.0.lock().expect("buffer lock is not poisoned"),
            expected,
            "the stream holds the selected raw bytes in selection order"
        );
        assert_eq!(
            summary.messages,
            count(positions.len()),
            "the selection's size is counted"
        );
        assert_eq!(summary.path, None, "a stream has no path");
    }

    #[test]
    fn progress_rises_after_each_batch_and_ends_at_the_selection_size() {
        let fixture = Fixture::new();
        let seen: Arc<Mutex<Vec<Progress>>> = Arc::default();
        let hook_seen = Arc::clone(&seen);
        let summary = fixture
            .export(Destination::File(fixture.target()))
            .on_progress(move |progress| {
                hook_seen
                    .lock()
                    .expect("lock is not poisoned")
                    .push(progress);
            })
            .run(Box::new(StreamSink))
            .expect("the export succeeds");

        let recorded = seen.lock().expect("lock is not poisoned").clone();
        let messages: Vec<u64> = recorded.iter().map(|progress| progress.messages).collect();
        assert_eq!(messages, [2, 4, 6, 7], "one batch at a time");
        assert!(
            recorded
                .iter()
                .all(|progress| progress.total == count(MESSAGES)),
            "the total is the selection size"
        );
        let bytes = recorded.last().map(|progress| progress.bytes);
        assert_eq!(bytes, Some(summary.bytes), "bytes end at the summary's");
    }

    #[test]
    fn a_sink_that_does_not_accept_the_destination_fails_before_staging() {
        let fixture = Fixture::new();
        fs::write(fixture.target(), b"previous").expect("existing target is written");
        let error = fixture
            .export(Destination::File(fixture.target()))
            .run(Box::new(DirectorySink { written: 0 }))
            .expect_err("a directory sink refuses a file destination");

        let MboxTurboError::UnsupportedDestination { kind, target } = error else {
            panic!("the refusal is an unsupported destination error");
        };
        assert_eq!(kind, DestinationKind::File, "the refused kind is named");
        assert_eq!(target, Some(fixture.target()), "the target is named");
        assert_eq!(
            fixture.leftovers(),
            ["target"],
            "nothing was staged beside the target"
        );
    }

    #[test]
    fn an_existing_target_is_refused_unless_replacing() {
        let fixture = Fixture::new();
        fs::write(fixture.target(), b"previous").expect("existing target is written");

        let error = fixture
            .export(Destination::File(fixture.target()))
            .run(Box::new(StreamSink))
            .expect_err("the existing target is refused");
        assert!(
            matches!(error, MboxTurboError::TargetExists { .. }),
            "refusal names the target"
        );

        drop(
            fixture
                .export(Destination::File(fixture.target()))
                .overwrite(Overwrite::Replace)
                .run(Box::new(StreamSink))
                .expect("replacing the target succeeds"),
        );
        assert_eq!(
            fs::read(fixture.target()).expect("target is readable"),
            fixture.raw_messages().concat(),
            "the target holds the new output"
        );
    }

    #[test]
    fn cancelling_from_another_thread_stops_within_one_batch_and_leaves_nothing() {
        let fixture = Fixture::new();
        let token = CancelToken::new();
        let hook_token = token.clone();
        let error = fixture
            .export(Destination::Directory(fixture.target()))
            .cancel_token(token.clone())
            .on_progress(move |_progress| {
                let remote = hook_token.clone();
                thread::spawn(move || remote.cancel())
                    .join()
                    .expect("cancelling thread finishes");
            })
            .run(Box::new(DirectorySink { written: 0 }))
            .expect_err("the export is cancelled");

        assert!(token.is_cancelled(), "the token is shared between clones");
        let MboxTurboError::Cancelled { target, written } = error else {
            panic!("cancellation is its own error");
        };
        assert_eq!(target, Some(fixture.target()), "the target is named");
        assert_eq!(
            written,
            count(BATCH_SIZE),
            "exactly the batch in flight was written"
        );
        assert!(
            fixture.leftovers().is_empty(),
            "nothing is left at or beside the target"
        );
    }

    #[test]
    fn a_sink_error_part_way_leaves_nothing_at_a_file_or_directory_target() {
        let cases: [Case; 2] = [
            (Destination::File, Box::new(StreamSink)),
            (
                Destination::Directory,
                Box::new(DirectorySink { written: 0 }),
            ),
        ];
        for (destination, inner) in cases {
            let fixture = Fixture::new();
            let error = fixture
                .export(destination(fixture.target()))
                .run(Box::new(FailAfter { batches: 1, inner }))
                .expect_err("the sink fails on its second batch");

            assert!(
                matches!(&error, MboxTurboError::Io { path, .. } if path == Path::new("sink")),
                "the sink's own error is returned"
            );
            assert!(
                fixture.leftovers().is_empty(),
                "nothing is left at or beside the target"
            );
        }
    }

    #[test]
    fn a_sink_error_from_finish_is_returned_and_leaves_nothing() {
        let cases: [Case; 2] = [
            (Destination::File, Box::new(StreamSink)),
            (
                Destination::Directory,
                Box::new(DirectorySink { written: 0 }),
            ),
        ];
        for (destination, inner) in cases {
            let fixture = Fixture::new();
            let error = fixture
                .export(destination(fixture.target()))
                .run(Box::new(FailFinish { inner }))
                .expect_err("the sink fails when it finishes");

            assert!(
                matches!(&error, MboxTurboError::Io { path, .. } if path == Path::new("finish")),
                "the sink's own error is returned"
            );
            assert!(
                fixture.leftovers().is_empty(),
                "nothing is left at or beside the target"
            );
        }
    }

    /// The schema and batches of the Parquet file at `path`, read with the Arrow reader.
    fn read_parquet(path: &Path) -> (SchemaRef, Vec<RecordBatch>) {
        let file = File::open(path).expect("exported parquet file opens");
        let builder =
            ParquetRecordBatchReaderBuilder::try_new(file).expect("parquet footer is readable");
        let schema = SchemaRef::clone(builder.schema());
        let batches = builder
            .build()
            .expect("parquet reader builds")
            .collect::<Result<Vec<_>, _>>()
            .expect("every parquet batch is decoded");
        (schema, batches)
    }

    /// A fixture whose pipeline extracts the default columns, and the batches `Pipeline::select`
    /// yields for the same columns over the whole mailbox, in one batch so they compare with a
    /// file read back whole.
    fn default_columns_fixture() -> (Fixture, Vec<RecordBatch>) {
        let mut fixture = Fixture::new();
        fixture.pipeline = Arc::new(Pipeline::new(Column::defaults(), BATCH_SIZE));
        let whole = Arc::new(Pipeline::new(Column::defaults(), MESSAGES));
        let expected = whole
            .select(&fixture.mailbox, Selection::All)
            .expect("the whole mailbox is selectable")
            .collect::<Result<Vec<_>, _>>()
            .expect("every batch is assembled");
        assert_eq!(
            expected.len(),
            1,
            "the pipeline yields every message in one batch"
        );
        (fixture, expected)
    }

    #[test]
    fn a_parquet_file_from_the_driver_reads_back_as_the_batches_the_pipeline_yields() {
        let (fixture, expected) = default_columns_fixture();
        let summary = fixture
            .export(Destination::File(fixture.target()))
            .run(Box::new(ParquetExporter::new(Compression::Zstd)))
            .expect("the parquet export succeeds");

        let (schema, batches) = read_parquet(&fixture.target());
        assert_eq!(
            Some(&schema),
            expected.first().map(RecordBatch::schema_ref),
            "the Arrow schema is the pipeline's"
        );
        assert_eq!(batches, expected, "rows and values are the pipeline's");
        assert_eq!(
            summary.messages,
            count(MESSAGES),
            "every message is counted"
        );
        let file = fs::read(fixture.target()).expect("exported file is readable");
        assert_eq!(
            summary.bytes,
            count(file.len()),
            "the reported bytes are the committed file's length"
        );
    }

    #[test]
    fn a_parquet_sink_handed_a_directory_refuses_it_instead_of_writing_nothing() {
        let (fixture, expected) = default_columns_fixture();
        let batch = expected.first().expect("the pipeline yields a batch");
        let mut staged = Destination::Directory(fixture.target())
            .stage(Overwrite::Refuse)
            .expect("a directory destination stages");
        let mut sink = ParquetExporter::new(Compression::Zstd);
        sink.begin(batch.schema_ref(), &mut staged)
            .expect("the encoder starts without touching the output");

        let refusal = sink.write(batch, &mut staged);

        assert!(
            matches!(
                refusal,
                Err(MboxTurboError::UnsupportedDestination {
                    kind: DestinationKind::Directory,
                    target: Some(_),
                })
            ),
            "a directory is refused with its kind and target, not reported as zero bytes"
        );
    }

    #[test]
    fn a_parquet_stream_holds_the_same_rows_as_the_pipeline_yields() {
        let (fixture, expected) = default_columns_fixture();
        let streamed = fixture.output.path().join("streamed.parquet");
        let summary = fixture
            .export(Destination::Stream(Box::new(
                File::create(&streamed).expect("stream file creates"),
            )))
            .run(Box::new(ParquetExporter::new(Compression::Zstd)))
            .expect("the parquet stream export succeeds");

        let (schema, batches) = read_parquet(&streamed);
        assert_eq!(
            Some(&schema),
            expected.first().map(RecordBatch::schema_ref),
            "the Arrow schema is the pipeline's"
        );
        assert_eq!(
            batches, expected,
            "a stream carries the same rows as the pipeline yields"
        );
        assert_eq!(summary.path, None, "a stream has no path");
        let written = fs::read(&streamed).expect("streamed file is readable");
        assert_eq!(
            summary.bytes,
            count(written.len()),
            "the reported bytes are the streamed buffer's length"
        );
    }

    #[test]
    fn the_parquet_sink_refuses_a_directory_before_staging_anything() {
        let fixture = Fixture::new();
        fs::create_dir_all(fixture.target()).expect("existing target is created");
        let error = fixture
            .export(Destination::Directory(fixture.target()))
            .run(Box::new(ParquetExporter::new(Compression::Zstd)))
            .expect_err("parquet cannot fill a directory");

        assert!(
            matches!(
                error,
                MboxTurboError::UnsupportedDestination {
                    kind: DestinationKind::Directory,
                    ..
                }
            ),
            "the refused kind is the directory"
        );
        assert_eq!(
            fixture.leftovers(),
            ["target"],
            "nothing was staged beside the target"
        );
    }

    fn count(length: usize) -> u64 {
        u64::try_from(length).expect("a length fits in u64")
    }
}
