//! The mbox sink writes the selected messages' stored bytes, so the exported file opens as a
//! mailbox of the same messages in selection order.

#[cfg(test)]
mod export_mbox {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;

    use mboxturbo::{
        CancelToken, Column, Destination, Export, Mailbox, MboxExporter, MboxTurboError, Pipeline,
        Selection,
    };
    use tempfile::TempDir;

    const BATCH_SIZE: usize = 2;
    const MAILBOX: &[u8] =
        b"From a@example.com Mon Jan  1 00:00:00 2024\nSubject: zero\n\nbody zero\n\n\
        From b@example.com Mon Jan  1 00:00:00 2024\nSubject: one\n\nquoted:\n>From the past\n\n\
        From c@example.com Mon Jan  1 00:00:00 2024\nSubject: two\n\nbody two\n\n\
        From d@example.com Mon Jan  1 00:00:00 2024\nSubject: three\n\nno final newline";

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

        fn raw(&self, position: usize) -> Vec<u8> {
            self.mailbox
                .raw(position)
                .expect("the message exists at that position")
                .to_vec()
        }

        fn target(&self) -> PathBuf {
            self.output.path().join("exported.mbox")
        }
    }

    #[test]
    fn an_exported_selection_reopens_as_the_same_messages_in_selection_order() {
        let fixture = Fixture::new();
        drop(
            fixture
                .export(vec![Column::Raw], Destination::File(fixture.target()))
                .selection(Selection::Positions(vec![2, 0, 1]))
                .run(Box::new(MboxExporter::new()))
                .expect("the export succeeds"),
        );

        let exported = Mailbox::open(fixture.target()).expect("the exported file opens");
        assert_eq!(exported.len(), 3, "one message per selected position");
        for (position, source) in [2, 0, 1].into_iter().enumerate() {
            assert_eq!(
                exported.raw(position).expect("the message exists"),
                fixture.raw(source).as_slice(),
                "message {position} carries the stored bytes of position {source}"
            );
        }
    }

    #[test]
    fn a_message_without_a_final_newline_gets_one_so_the_next_from_line_starts_a_line() {
        let fixture = Fixture::new();
        let summary = fixture
            .export(vec![Column::Raw], Destination::File(fixture.target()))
            .selection(Selection::Positions(vec![3, 0]))
            .run(Box::new(MboxExporter::new()))
            .expect("the export succeeds");

        let mut expected = fixture.raw(3);
        expected.push(b'\n');
        expected.extend(fixture.raw(0));
        assert_eq!(
            fs::read(fixture.target()).expect("the target is readable"),
            expected,
            "exactly one newline is appended after the unterminated message"
        );
        assert_eq!(
            summary.bytes,
            u64::try_from(expected.len()).expect("a length fits in u64"),
            "the appended newline is counted"
        );
    }

    #[test]
    fn a_stream_destination_receives_the_same_bytes_as_a_file() {
        let fixture = Fixture::new();
        let stream = fixture.target();
        let file = fs::File::create(&stream).expect("the stream file is created");
        drop(
            fixture
                .export(vec![Column::Raw], Destination::Stream(Box::new(file)))
                .selection(Selection::Positions(vec![1]))
                .run(Box::new(MboxExporter::new()))
                .expect("the stream export succeeds"),
        );

        assert_eq!(
            fs::read(&stream).expect("the stream file is readable"),
            fixture.raw(1),
            "the stream holds the stored bytes"
        );
    }

    #[test]
    fn a_directory_destination_is_refused() {
        let fixture = Fixture::new();
        let error = fixture
            .export(vec![Column::Raw], Destination::Directory(fixture.target()))
            .run(Box::new(MboxExporter::new()))
            .expect_err("the sink refuses a directory");

        assert!(
            matches!(error, MboxTurboError::UnsupportedDestination { .. }),
            "the refusal is an unsupported destination error"
        );
        assert!(!fixture.target().exists(), "nothing was written");
    }

    #[test]
    fn a_schema_without_the_raw_column_is_refused_naming_it_before_anything_is_written() {
        let fixture = Fixture::new();
        let error = fixture
            .export(vec![Column::Subject], Destination::File(fixture.target()))
            .run(Box::new(MboxExporter::new()))
            .expect_err("the sink needs the raw column");

        let MboxTurboError::UnsupportedColumn { column, sink, .. } = error else {
            panic!("the refusal is an unsupported column error");
        };
        assert_eq!(sink, "mbox", "the sink is named");
        assert_eq!(column, "raw", "the raw column is named");
        assert!(!fixture.target().exists(), "nothing was written");
    }

    #[test]
    fn a_cancelled_export_fails_with_cancelled_and_leaves_nothing_at_the_target() {
        let fixture = Fixture::new();
        let token = CancelToken::new();
        let hook_token = token.clone();
        let error = fixture
            .export(vec![Column::Raw], Destination::File(fixture.target()))
            .cancel_token(token)
            .on_progress(move |_progress| hook_token.cancel())
            .run(Box::new(MboxExporter::new()))
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
            .export(vec![Column::Raw], Destination::File(fixture.target()))
            .selection(Selection::Positions(vec![0, 1, 99]))
            .run(Box::new(MboxExporter::new()))
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
