//! The JSONL sink writes one JSON object per selected message, decoding to the same values a
//! select of the same columns yields, and leaves nothing behind when an export stops early.

#[cfg(test)]
mod export_jsonl {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::{fs, io};

    use arrow_array::cast::AsArray as _;
    use arrow_array::types::{Int32Type, TimestampMicrosecondType, UInt64Type};
    use arrow_array::{Array as _, ArrayRef, RecordBatch};
    use arrow_schema::{DataType, Field, Schema, SchemaRef};
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use mail_parser::DateTime;
    use mboxturbo::{
        CancelToken, Column, Destination, Export, Exporter, JsonlExporter, Mailbox, MboxTurboError,
        Overwrite, Pipeline, Selection, Staged,
    };
    use serde_json::{Map, Value};
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
        inner: JsonlExporter,
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
            self.output.path().join("exported.jsonl")
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

    fn strings(array: &ArrayRef) -> Vec<Value> {
        array
            .as_string::<i32>()
            .iter()
            .map(|item| Value::from(item.expect("a list item is present")))
            .collect()
    }

    /// The value the file should hold for `array` at `row`, built from the Arrow values.
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "the test selects only the types handled above"
    )]
    fn expected(array: &ArrayRef, row: usize) -> Value {
        if array.is_null(row) {
            return Value::Null;
        }
        match array.data_type() {
            DataType::Utf8 => Value::from(array.as_string::<i32>().value(row)),
            DataType::UInt64 => Value::from(array.as_primitive::<UInt64Type>().value(row)),
            DataType::Int32 => Value::from(array.as_primitive::<Int32Type>().value(row)),
            DataType::List(_) => Value::Array(strings(&array.as_list::<i32>().value(row))),
            other => panic!("the test selects no column of type {other}"),
        }
    }

    fn assert_row(object: &Map<String, Value>, batch: &RecordBatch, row: usize) {
        assert_eq!(object.len(), batch.num_columns(), "one key per column");
        for (index, field) in batch.schema().fields().iter().enumerate() {
            assert_cell(&object[field.name()], batch.column(index), row);
        }
    }

    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "every other selected type compares as plain JSON"
    )]
    fn assert_cell(actual: &Value, array: &ArrayRef, row: usize) {
        match array.data_type() {
            DataType::LargeBinary => {
                let text = actual.as_str().expect("raw is a string");
                assert_eq!(
                    STANDARD.decode(text).expect("raw is standard base64"),
                    array.as_binary::<i64>().value(row),
                    "raw decodes to the stored bytes"
                );
            },
            DataType::Timestamp(..) if array.is_null(row) => {
                assert!(actual.is_null(), "a message without a date has a null date");
            },
            DataType::Timestamp(..) => {
                let parsed = DateTime::parse_rfc3339(actual.as_str().expect("date is a string"))
                    .expect("the date is RFC 3339");
                assert_eq!(
                    parsed.to_timestamp(),
                    array
                        .as_primitive::<TimestampMicrosecondType>()
                        .value(row)
                        .div_euclid(1_000_000),
                    "the date parses to the selected instant"
                );
            },
            _ => assert_eq!(*actual, expected(array, row), "the value equals the select"),
        }
    }

    #[test]
    fn the_file_decodes_to_the_values_of_a_select_of_the_same_columns_and_positions() {
        let fixture = Fixture::new();
        let positions = vec![2, 1, 0, 3];
        drop(
            fixture
                .export(all_columns(), Destination::File(fixture.target()))
                .selection(Selection::Positions(positions.clone()))
                .run(Box::new(JsonlExporter::new()))
                .expect("the export succeeds"),
        );

        let text = fs::read_to_string(fixture.target()).expect("the target is readable");
        let mut lines = text.lines();
        for batch in selected(&fixture, &all_columns(), positions) {
            for row in 0..batch.num_rows() {
                let line = lines.next().expect("one line per selected message");
                let object: Map<String, Value> =
                    serde_json::from_str(line).expect("the line is a JSON object");
                assert_row(&object, &batch, row);
            }
        }
        assert_eq!(lines.next(), None, "no line beyond the selection");
    }

    fn exported_line(fixture: &Fixture, position: usize) -> String {
        drop(
            fixture
                .export(all_columns(), Destination::File(fixture.target()))
                .selection(Selection::Positions(vec![position]))
                .run(Box::new(JsonlExporter::new()))
                .expect("the export succeeds"),
        );
        fs::read_to_string(fixture.target()).expect("the target is readable")
    }

    #[test]
    fn keys_follow_the_selection_column_order_and_the_line_ends_in_a_newline() {
        let line = exported_line(&Fixture::new(), 1);
        let offsets: Vec<usize> = all_columns()
            .iter()
            .map(|column| {
                line.find(&format!("\"{}\":", column.name()))
                    .expect("every column is a key")
            })
            .collect();

        assert!(offsets.is_sorted(), "keys appear in selection order");
        assert_eq!(
            line.as_bytes().last(),
            Some(&b'\n'),
            "the line is newline-terminated"
        );
    }

    #[test]
    fn missing_values_are_null_or_empty_lists_and_text_is_escaped() {
        let line = exported_line(&Fixture::new(), 1);
        let object: Map<String, Value> = serde_json::from_str(&line).expect("one JSON object");

        assert_eq!(object["date"], Value::Null, "a missing date is null");
        assert_eq!(
            object["to"],
            Value::Array(Vec::new()),
            "a message without recipients has an empty list"
        );
        assert_eq!(
            object["position"],
            Value::from(1_u64),
            "integers are numbers"
        );
        assert_eq!(
            object["subject"],
            Value::from("one \"quoted\""),
            "text is a JSON-escaped string"
        );
    }

    #[test]
    fn a_stream_destination_receives_the_same_bytes_as_a_file() {
        let fixture = Fixture::new();
        let file_target = fixture.target();
        drop(
            fixture
                .export(all_columns(), Destination::File(file_target.clone()))
                .run(Box::new(JsonlExporter::new()))
                .expect("the file export succeeds"),
        );
        let stream_target = fixture.output.path().join("stream.jsonl");
        let stream = fs::File::create(&stream_target).expect("the stream file is created");
        drop(
            fixture
                .export(all_columns(), Destination::Stream(Box::new(stream)))
                .run(Box::new(JsonlExporter::new()))
                .expect("the stream export succeeds"),
        );

        assert_eq!(
            fs::read(&stream_target).expect("the stream file is readable"),
            fs::read(&file_target).expect("the file is readable"),
            "both destinations hold the same lines"
        );
    }

    #[test]
    fn a_directory_destination_is_refused() {
        let fixture = Fixture::new();
        let error = fixture
            .export(all_columns(), Destination::Directory(fixture.target()))
            .run(Box::new(JsonlExporter::new()))
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
            .run(Box::new(JsonlExporter::new()))
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
                inner: JsonlExporter::new(),
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

    #[test]
    fn a_column_type_the_sink_cannot_encode_is_refused_naming_it_before_anything_is_written() {
        let fixture = Fixture::new();
        let mut staged = Destination::File(fixture.target())
            .stage(Overwrite::Refuse)
            .expect("the destination stages");
        let schema = Arc::new(Schema::new(vec![
            Field::new("subject", DataType::Utf8, true),
            Field::new("ratio", DataType::Float64, true),
        ]));
        let error = JsonlExporter::new()
            .begin(&schema, &mut staged)
            .expect_err("a float column cannot be encoded");

        let MboxTurboError::UnsupportedColumn { column, sink, .. } = error else {
            panic!("the refusal is an unsupported column error");
        };
        assert_eq!(sink, "JSONL", "the sink is named");
        assert_eq!(column, "ratio", "the column is named");
        assert!(
            fs::read(fixture.target()).map_or(true, |bytes| bytes.is_empty()),
            "nothing was written"
        );
    }
}
