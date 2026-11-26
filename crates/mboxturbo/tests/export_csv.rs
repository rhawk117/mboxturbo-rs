//! The CSV sink writes a header and one RFC 4180 row per selected message, defuses spreadsheet
//! formulas by default, and leaves nothing behind when an export stops early.

#[cfg(test)]
mod export_csv {
    use std::iter::Peekable;
    use std::path::PathBuf;
    use std::str::Chars;
    use std::sync::Arc;
    use std::{fs, io};

    use arrow_array::RecordBatch;
    use arrow_schema::{ArrowError, DataType, Field, Schema, SchemaRef};
    use mboxturbo::{
        CancelToken, Column, CsvExporter, Destination, Export, Exporter, FormulaEscaping, Mailbox,
        MboxTurboError, Overwrite, Pipeline, Staged,
    };
    use tempfile::TempDir;

    const BATCH_SIZE: usize = 2;
    const MAILBOX: &[u8] = concat!(
        "From a@example.com Mon Jan  1 00:00:00 2024\n",
        "Subject: =?UTF-8?Q?a=2C_=22b=22=0D=0Ac?=\n",
        "Date: Mon, 1 Jan 2024 08:00:00 +0000\n",
        "To: x@example.com, y@example.com\n\nbody zero\n\n",
        "From b@example.com Mon Jan  1 00:00:00 2024\n",
        "Subject: =1+1\n",
        "Date: Mon, 1 Jan 2024 09:30:15 -0500\n\nbody one\n\n",
        "From c@example.com Mon Jan  1 00:00:00 2024\n",
        "Subject: +plus\n\nbody two\n\n",
        "From d@example.com Mon Jan  1 00:00:00 2024\n",
        "Subject: -minus\n\nbody three\n\n",
        "From e@example.com Mon Jan  1 00:00:00 2024\n",
        "Subject: @at\n\nbody four\n\n",
        "From f@example.com Mon Jan  1 00:00:00 2024\n",
        "Subject: =?UTF-8?Q?=09tab?=\n\nbody five\n\n",
        "From g@example.com Mon Jan  1 00:00:00 2024\n",
        "Subject: =?UTF-8?Q?=0Dcr?=\n\nbody six\n\n",
        "From h@example.com Mon Jan  1 00:00:00 2024\n",
        "To: z@example.com\n\nno subject, no final newline",
    )
    .as_bytes();

    /// Delegates to another sink until `batches` have been written, then fails.
    struct FailAfter {
        batches: usize,
        inner: CsvExporter,
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
            self.output.path().join("exported.csv")
        }
    }

    fn columns() -> Vec<Column> {
        vec![
            Column::Position,
            Column::Subject,
            Column::Date,
            Column::To,
            Column::DateOffsetMinutes,
        ]
    }

    fn export_text(escaping: FormulaEscaping) -> String {
        let fixture = Fixture::new();
        drop(
            fixture
                .export(columns(), Destination::File(fixture.target()))
                .run(Box::new(CsvExporter::new(escaping)))
                .expect("the export succeeds"),
        );
        fs::read_to_string(fixture.target()).expect("the target is readable")
    }

    fn parse_field(chars: &mut Peekable<Chars<'_>>) -> String {
        let mut field = String::new();
        if chars.next_if_eq(&'"').is_none() {
            while let Some(next) = chars.next_if(|next| !matches!(next, ',' | '\r')) {
                field.push(next);
            }
            return field;
        }
        while let Some(next) = chars.next() {
            if next == '"' && chars.next_if_eq(&'"').is_none() {
                break;
            }
            field.push(next);
        }
        field
    }

    fn parse_record(chars: &mut Peekable<Chars<'_>>) -> Vec<String> {
        let mut record = vec![parse_field(chars)];
        while chars.next_if_eq(&',').is_some() {
            record.push(parse_field(chars));
        }
        if chars.next_if_eq(&'\r').is_some() {
            assert_eq!(chars.next(), Some('\n'), "a CR ends the row only as CRLF");
        }
        record
    }

    /// A minimal RFC 4180 reader: quoted fields, doubled quotes, CRLF row ends.
    fn parse_csv(text: &str) -> Vec<Vec<String>> {
        let mut chars = text.chars().peekable();
        let mut rows = Vec::new();
        while chars.peek().is_some() {
            rows.push(parse_record(&mut chars));
        }
        rows
    }

    fn cell(rows: &[Vec<String>], row: usize, column: &str) -> String {
        let index = rows[0]
            .iter()
            .position(|name| name == column)
            .expect("the column is in the header");
        rows[row.saturating_add(1)][index].clone()
    }

    #[test]
    fn the_header_names_the_columns_in_selection_order_and_every_row_ends_in_crlf() {
        let text = export_text(FormulaEscaping::Prefix);
        let rows = parse_csv(&text);

        assert_eq!(
            rows[0],
            ["position", "subject", "date", "to", "date_offset_minutes"],
            "the header holds the selected names in order"
        );
        assert_eq!(rows.len(), 9, "one row per message after the header");
        assert_eq!(
            text.split_inclusive("\r\n").next(),
            Some("position,subject,date,to,date_offset_minutes\r\n"),
            "the header row ends in CRLF"
        );
        assert_eq!(
            text.as_bytes().last(),
            Some(&b'\n'),
            "the last row ends in CRLF"
        );
    }

    #[test]
    fn text_cells_that_look_like_formulas_are_prefixed_with_an_apostrophe() {
        let rows = parse_csv(&export_text(FormulaEscaping::Prefix));

        let subjects: Vec<String> = (1..=6).map(|row| cell(&rows, row, "subject")).collect();
        assert_eq!(
            subjects,
            ["'=1+1", "'+plus", "'-minus", "'@at", "'\ttab", "'\rcr"],
            "each trigger character gets the prefix"
        );
        assert_eq!(
            cell(&rows, 0, "subject"),
            "a, \"b\"\r\nc",
            "a cell that is not a formula is only quoted"
        );
    }

    #[test]
    fn numeric_cells_are_never_prefixed() {
        let rows = parse_csv(&export_text(FormulaEscaping::Prefix));

        assert_eq!(
            cell(&rows, 1, "date_offset_minutes"),
            "-300",
            "a negative offset stays a plain number"
        );
        assert_eq!(cell(&rows, 1, "position"), "1", "positions stay plain");
    }

    #[test]
    fn lists_are_json_dates_are_rfc_3339_and_missing_values_are_empty() {
        let rows = parse_csv(&export_text(FormulaEscaping::Prefix));

        assert_eq!(
            cell(&rows, 0, "to"),
            "[\"x@example.com\",\"y@example.com\"]",
            "a list is one JSON cell"
        );
        assert_eq!(
            cell(&rows, 1, "date"),
            "2024-01-01T14:30:15Z",
            "the date is UTC RFC 3339"
        );
        assert_eq!(cell(&rows, 2, "date"), "", "a missing date is empty");
        assert_eq!(cell(&rows, 7, "subject"), "", "a missing subject is empty");
    }

    #[test]
    fn with_escaping_off_an_rfc_4180_reader_recovers_the_selected_values_exactly() {
        let rows = parse_csv(&export_text(FormulaEscaping::Off));

        let subjects: Vec<String> = (0..=6).map(|row| cell(&rows, row, "subject")).collect();
        assert_eq!(
            subjects,
            [
                "a, \"b\"\r\nc",
                "=1+1",
                "+plus",
                "-minus",
                "@at",
                "\ttab",
                "\rcr"
            ],
            "commas, quotes, CR and LF round-trip"
        );
    }

    #[test]
    fn a_stream_destination_receives_the_same_bytes_as_a_file() {
        let fixture = Fixture::new();
        let file_target = fixture.target();
        drop(
            fixture
                .export(columns(), Destination::File(file_target.clone()))
                .run(Box::new(CsvExporter::new(FormulaEscaping::Prefix)))
                .expect("the file export succeeds"),
        );
        let stream_target = fixture.output.path().join("stream.csv");
        let stream = fs::File::create(&stream_target).expect("the stream file is created");
        drop(
            fixture
                .export(columns(), Destination::Stream(Box::new(stream)))
                .run(Box::new(CsvExporter::new(FormulaEscaping::Prefix)))
                .expect("the stream export succeeds"),
        );

        assert_eq!(
            fs::read(&stream_target).expect("the stream file is readable"),
            fs::read(&file_target).expect("the file is readable"),
            "both destinations hold the same rows"
        );
    }

    #[test]
    fn a_directory_destination_is_refused() {
        let fixture = Fixture::new();
        let error = fixture
            .export(columns(), Destination::Directory(fixture.target()))
            .run(Box::new(CsvExporter::new(FormulaEscaping::Prefix)))
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
            .export(columns(), Destination::File(fixture.target()))
            .cancel_token(token)
            .on_progress(move |_progress| hook_token.cancel())
            .run(Box::new(CsvExporter::new(FormulaEscaping::Prefix)))
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
            .export(columns(), Destination::File(fixture.target()))
            .run(Box::new(FailAfter {
                batches: 1,
                inner: CsvExporter::new(FormulaEscaping::Prefix),
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
    fn raw_is_refused_naming_the_column_before_anything_is_written() {
        let fixture = Fixture::new();
        let error = fixture
            .export(
                vec![Column::Subject, Column::Raw],
                Destination::File(fixture.target()),
            )
            .run(Box::new(CsvExporter::new(FormulaEscaping::Prefix)))
            .expect_err("raw cannot be a CSV cell");

        let MboxTurboError::Arrow {
            source: ArrowError::SchemaError(message),
            ..
        } = error
        else {
            panic!("the refusal is an Arrow schema error");
        };
        assert!(message.contains("`raw`"), "the column is named");
        assert!(
            fixture.leftovers().is_empty(),
            "nothing is left at or beside the target"
        );
    }

    #[test]
    fn a_column_type_the_sink_cannot_encode_is_refused_naming_it() {
        let fixture = Fixture::new();
        let mut staged = Destination::File(fixture.target())
            .stage(Overwrite::Refuse)
            .expect("the destination stages");
        let schema = Arc::new(Schema::new(vec![
            Field::new("subject", DataType::Utf8, true),
            Field::new("ratio", DataType::Float64, true),
        ]));
        let error = CsvExporter::new(FormulaEscaping::Prefix)
            .begin(&schema, &mut staged)
            .expect_err("a float column cannot be encoded");

        let MboxTurboError::Arrow {
            source: ArrowError::SchemaError(message),
            ..
        } = error
        else {
            panic!("the refusal is an Arrow schema error");
        };
        assert!(message.contains("`ratio`"), "the column is named");
        assert!(
            fs::read(fixture.target()).map_or(true, |bytes| bytes.is_empty()),
            "nothing was written"
        );
    }
}
