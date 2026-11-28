//! The EML sink names each file by the message's position and never by its content, and lists
//! the exported messages in a manifest.

#[cfg(test)]
mod export_eml {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;

    use mboxturbo::{
        CancelToken, Column, Destination, EmlExporter, Export, Mailbox, MboxTurboError, Pipeline,
        Selection,
    };
    use serde_json::{Value, json};
    use tempfile::TempDir;

    const BATCH_SIZE: usize = 4;
    const HOSTILE_ID: &str = "<..\\..\\C:\\evil/../../escape\0@host>";
    const HOSTILE_SUBJECT: &[u8] = b"../../etc/passwd C:\\boot.ini \\\\server\\share \0 /abs";
    const MESSAGES: usize = 12;
    /// The files the EML sink writes for [`QUOTED_MBOX`].
    const QUOTED_FILES: [(&str, &[u8]); 4] = [
        (
            "0.eml",
            b"Subject: plain\n\nhello\n> a quoted reply\nsee >From inline\n\n",
        ),
        (
            "1.eml",
            b"Subject: quoted\n\nbody\nFrom quoted\n>From twice\n>Fromage\n\n",
        ),
        (
            "2.eml",
            b"From the first line\nSubject: leading\n\nbody\n\n",
        ),
        (
            "3.eml",
            b"> not a From line\nSubject: leading reply\n\nbody\n\n",
        ),
    ];
    /// The manifest the EML sink writes for [`QUOTED_MBOX`] with only `raw` and `position`.
    const QUOTED_MANIFEST: &str = "\
        {\"date\":null,\"file\":\"0.eml\",\"message_id\":null,\"position\":0}\n\
        {\"date\":null,\"file\":\"1.eml\",\"message_id\":null,\"position\":1}\n\
        {\"date\":null,\"file\":\"2.eml\",\"message_id\":null,\"position\":2}\n\
        {\"date\":null,\"file\":\"3.eml\",\"message_id\":null,\"position\":3}\n";
    /// One message with no `>+From ` line, two with one in the body or on the first line, and one
    /// whose first line is quoted but not a `From ` line.
    const QUOTED_MBOX: &[u8] = b"From a@example.com Mon Jan  1 00:00:00 2024\n\
        Subject: plain\n\nhello\n> a quoted reply\nsee >From inline\n\n\
        From b@example.com Mon Jan  1 00:00:00 2024\n\
        Subject: quoted\n\nbody\n>From quoted\n>>From twice\n>Fromage\n\n\
        From c@example.com Mon Jan  1 00:00:00 2024\n\
        >From the first line\nSubject: leading\n\nbody\n\n\
        From d@example.com Mon Jan  1 00:00:00 2024\n\
        > not a From line\nSubject: leading reply\n\nbody\n\n";

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

        fn manifest(&self) -> Vec<Value> {
            fs::read_to_string(self.target().join("manifest.jsonl"))
                .expect("the manifest is readable")
                .lines()
                .map(|line| serde_json::from_str(line).expect("each manifest line is JSON"))
                .collect()
        }

        fn new() -> Self {
            Self::with_messages(MESSAGES)
        }

        fn raw(&self, position: usize) -> Vec<u8> {
            self.mailbox
                .raw(position)
                .expect("the message exists at that position")
                .to_vec()
        }

        fn target(&self) -> PathBuf {
            self.output.path().join("eml")
        }

        fn with_mbox(mbox: &[u8]) -> Self {
            let input = tempfile::tempdir().expect("input directory creates");
            let path = input.path().join("inbox.mbox");
            fs::write(&path, mbox).expect("fixture mbox is written");
            Self {
                mailbox: Arc::new(Mailbox::open(&path).expect("fixture mbox opens")),
                _input: input,
                output: tempfile::tempdir().expect("output directory creates"),
            }
        }

        fn with_messages(count: usize) -> Self {
            let mbox: Vec<u8> = (0..count).flat_map(message).collect();
            Self::with_mbox(&mbox)
        }
    }

    fn all_columns() -> Vec<Column> {
        vec![
            Column::Raw,
            Column::Position,
            Column::MessageId,
            Column::Date,
        ]
    }

    fn message(number: usize) -> Vec<u8> {
        let headers = match number {
            3 => format!(
                "Subject: {}\nMessage-ID: {HOSTILE_ID}\n",
                String::from_utf8_lossy(HOSTILE_SUBJECT)
            ),
            5 => "Subject: undated\n".to_owned(),
            _ => format!(
                "Subject: message {number}\nMessage-ID: <m{number}@example.com>\n\
                Date: Mon, 1 Jan 2024 10:00:{number:02} +0200\n"
            ),
        };
        format!(
            "From a@example.com Mon Jan  1 00:00:00 2024\n{headers}\n\
            body\n>From quoted\n>>From twice\n>Fromage\n\n"
        )
        .into_bytes()
    }

    fn names(fixture: &Fixture) -> Vec<String> {
        let mut found: Vec<String> = fs::read_dir(fixture.target())
            .expect("the target directory is readable")
            .map(|entry| {
                entry
                    .expect("the entry is readable")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        found.sort();
        found
    }

    #[test]
    fn files_are_named_by_zero_padded_position_and_hold_the_unquoted_message() {
        let fixture = Fixture::new();
        drop(
            fixture
                .export(all_columns(), Destination::Directory(fixture.target()))
                .selection(Selection::Positions(vec![7, 0]))
                .run(Box::new(EmlExporter::new(MESSAGES)))
                .expect("the export succeeds"),
        );

        assert_eq!(
            names(&fixture),
            ["00.eml", "07.eml", "manifest.jsonl"],
            "positions are padded to the width of the mailbox's largest count"
        );
        let raw = fixture.raw(7);
        let body_start = raw
            .iter()
            .position(|byte| *byte == b'\n')
            .expect("the From_ line ends")
            + 1;
        let mut expected = raw[body_start..].to_vec();
        expected = String::from_utf8(expected)
            .expect("the fixture is UTF-8")
            .replace("\n>From quoted", "\nFrom quoted")
            .replace("\n>>From twice", "\n>From twice")
            .into_bytes();
        assert_eq!(
            fs::read(fixture.target().join("07.eml")).expect("the file is readable"),
            expected,
            "no From_ line, one `>` removed from each `>+From ` line, `>Fromage` untouched"
        );
    }

    #[test]
    fn the_manifest_maps_positions_to_files_in_selection_order_with_nulls_for_missing_fields() {
        let fixture = Fixture::new();
        drop(
            fixture
                .export(all_columns(), Destination::Directory(fixture.target()))
                .selection(Selection::Positions(vec![9, 5, 1]))
                .run(Box::new(EmlExporter::new(MESSAGES)))
                .expect("the export succeeds"),
        );

        assert_eq!(
            fixture.manifest(),
            [
                json!({"position": 9_u64, "file": "09.eml", "message_id": "m9@example.com",
                    "date": "2024-01-01T08:00:09Z"}),
                json!({"position": 5_u64, "file": "05.eml", "message_id": null, "date": null}),
                json!({"position": 1_u64, "file": "01.eml", "message_id": "m1@example.com",
                    "date": "2024-01-01T08:00:01Z"}),
            ],
            "one object per message in selection order, null where the message has none"
        );
    }

    #[test]
    fn columns_the_export_did_not_extract_are_null_in_the_manifest() {
        let fixture = Fixture::new();
        drop(
            fixture
                .export(
                    vec![Column::Raw, Column::Position],
                    Destination::Directory(fixture.target()),
                )
                .selection(Selection::Positions(vec![2]))
                .run(Box::new(EmlExporter::new(MESSAGES)))
                .expect("the export succeeds"),
        );

        assert_eq!(
            fixture.manifest(),
            [json!({"position": 2_u64, "file": "02.eml", "message_id": null, "date": null})],
            "message_id and date are null when not extracted"
        );
    }

    #[test]
    fn a_hostile_subject_and_message_id_stay_inside_the_directory_under_the_position_name() {
        let fixture = Fixture::new();
        drop(
            fixture
                .export(all_columns(), Destination::Directory(fixture.target()))
                .selection(Selection::Positions(vec![3]))
                .run(Box::new(EmlExporter::new(MESSAGES)))
                .expect("the export succeeds"),
        );

        assert_eq!(
            names(&fixture),
            ["03.eml", "manifest.jsonl"],
            "only the position-named file and the manifest exist in the directory"
        );
        let siblings: Vec<_> = fs::read_dir(fixture.output.path())
            .expect("the output parent is readable")
            .collect();
        assert_eq!(
            siblings.len(),
            1,
            "nothing was written beside the directory"
        );
        assert_eq!(
            fixture.manifest()[0]["file"],
            "03.eml",
            "the manifest names the position file"
        );
    }

    #[test]
    fn a_batch_spread_over_several_workers_writes_the_same_files_as_a_one_worker_run() {
        let count = 600;
        let mut runs = Vec::new();
        for batch_size in [4, count] {
            let fixture = Fixture::with_messages(count);
            drop(
                Export::new(
                    Arc::new(Pipeline::new(all_columns(), batch_size)),
                    Arc::clone(&fixture.mailbox),
                    Destination::Directory(fixture.target()),
                )
                .run(Box::new(EmlExporter::new(count)))
                .expect("the export succeeds"),
            );
            let files: Vec<(String, Vec<u8>)> = names(&fixture)
                .into_iter()
                .map(|name| {
                    let bytes = fs::read(fixture.target().join(&name)).expect("the file reads");
                    (name, bytes)
                })
                .collect();
            runs.push(files);
        }

        assert_eq!(runs[0].len(), count + 1, "every message and the manifest");
        assert_eq!(
            runs[0], runs[1],
            "the same names and bytes whatever the worker count"
        );
    }

    #[test]
    fn quoted_and_unquoted_messages_are_written_as_the_expected_files_and_manifest() {
        let fixture = Fixture::with_mbox(QUOTED_MBOX);
        drop(
            fixture
                .export(
                    vec![Column::Raw, Column::Position],
                    Destination::Directory(fixture.target()),
                )
                .run(Box::new(EmlExporter::new(QUOTED_FILES.len())))
                .expect("the export succeeds"),
        );

        for (name, bytes) in QUOTED_FILES {
            assert_eq!(
                fs::read(fixture.target().join(name)).expect("the file is readable"),
                bytes,
                "{name}: no From_ line, one `>` removed from each `>+From ` line only"
            );
        }
        assert_eq!(
            fs::read_to_string(fixture.target().join("manifest.jsonl"))
                .expect("the manifest is readable"),
            QUOTED_MANIFEST,
            "one line per message in selection order"
        );
    }

    #[test]
    fn a_file_destination_is_refused() {
        let fixture = Fixture::new();
        let target = fixture.output.path().join("out.eml");
        let error = fixture
            .export(all_columns(), Destination::File(target.clone()))
            .run(Box::new(EmlExporter::new(MESSAGES)))
            .expect_err("the sink refuses a file");

        assert!(
            matches!(error, MboxTurboError::UnsupportedDestination { .. }),
            "the refusal is an unsupported destination error"
        );
        assert!(!target.exists(), "nothing was written");
    }

    #[test]
    fn a_schema_without_raw_or_position_is_refused_naming_the_column_before_anything_is_written() {
        for (columns, missing) in [
            (vec![Column::Position], "`raw`"),
            (vec![Column::Raw], "`position`"),
        ] {
            let fixture = Fixture::new();
            let error = fixture
                .export(columns, Destination::Directory(fixture.target()))
                .run(Box::new(EmlExporter::new(MESSAGES)))
                .expect_err("the sink needs both columns");

            let MboxTurboError::UnsupportedColumn { column, sink, .. } = error else {
                panic!("the refusal is an unsupported column error");
            };
            assert_eq!(sink, "EML", "the sink is named");
            assert_eq!(column, missing.trim_matches('`'), "{missing} is named");
            assert!(!fixture.target().exists(), "nothing was written");
        }
    }

    #[test]
    fn a_stream_destination_is_refused_and_writes_nothing() {
        let fixture = Fixture::new();
        let path = fixture.output.path().join("stream.out");
        let file = fs::File::create(&path).expect("the stream file is created");
        let error = fixture
            .export(all_columns(), Destination::Stream(Box::new(file)))
            .run(Box::new(EmlExporter::new(MESSAGES)))
            .expect_err("the sink refuses a stream");

        assert!(
            matches!(error, MboxTurboError::UnsupportedDestination { .. }),
            "the refusal is an unsupported destination error"
        );
        assert_eq!(
            fs::metadata(&path).expect("the stream file exists").len(),
            0,
            "nothing was written"
        );
    }

    #[test]
    fn a_cancelled_export_fails_with_cancelled_and_leaves_nothing_at_the_target() {
        let fixture = Fixture::new();
        let token = CancelToken::new();
        let hook_token = token.clone();
        let error = fixture
            .export(all_columns(), Destination::Directory(fixture.target()))
            .cancel_token(token)
            .on_progress(move |_progress| hook_token.cancel())
            .run(Box::new(EmlExporter::new(MESSAGES)))
            .expect_err("the export is cancelled");

        assert!(
            matches!(error, MboxTurboError::Cancelled { .. }),
            "cancellation is its own error"
        );
        assert!(
            fs::read_dir(fixture.output.path())
                .expect("the output directory is readable")
                .next()
                .is_none(),
            "nothing is left at or beside the target"
        );
    }

    #[test]
    fn a_failing_export_leaves_nothing_at_the_target() {
        let fixture = Fixture::new();
        let error = fixture
            .export(all_columns(), Destination::Directory(fixture.target()))
            .selection(Selection::Positions(vec![0, 1, 99]))
            .run(Box::new(EmlExporter::new(MESSAGES)))
            .expect_err("a position past the end fails the export");

        assert!(
            matches!(
                error,
                MboxTurboError::PositionOutOfRange { position: 99, .. }
            ),
            "the bad position is named"
        );
        assert!(
            fs::read_dir(fixture.output.path())
                .expect("the output directory is readable")
                .next()
                .is_none(),
            "nothing is left at or beside the target"
        );
    }
}
