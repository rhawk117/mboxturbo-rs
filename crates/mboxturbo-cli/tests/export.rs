//! The `mboxturbo export` subcommand writes each format from a small generated mailbox,
//! selects messages by position, and exits with the code of each failure.

#[cfg(test)]
mod export {
    use std::fs::{self, File};
    use std::io::Cursor;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};

    use arrow_array::RecordBatch;
    use arrow_array::cast::AsArray as _;
    use arrow_array::types::UInt64Type;
    use arrow_ipc::reader::StreamReader;
    use mboxturbo::Column;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use tempfile::TempDir;

    const MAILBOX: &str = concat!(
        "From a@example.com Mon Jan  1 00:00:00 2024\n",
        "Subject: zero\nFrom: a@example.com\n\nbody zero\n\n",
        "From b@example.com Mon Jan  1 00:00:00 2024\n",
        "Subject: one\nFrom: b@example.com\n\nbody one\n\n",
        "From c@example.com Mon Jan  1 00:00:00 2024\n",
        "Subject: two\nFrom: c@example.com\n\nbody two\n\n",
        "From d@example.com Mon Jan  1 00:00:00 2024\n",
        "Subject: three\nFrom: d@example.com\n\nbody three\n\n",
    );

    /// A temporary directory holding a four-message mailbox.
    struct Fixture {
        dir: TempDir,
        mbox: PathBuf,
    }

    impl Fixture {
        /// Runs `mboxturbo export <mailbox> <args>`.
        fn export(&self, args: &[&str]) -> Output {
            let mbox = self.mbox.to_str().expect("the fixture path is UTF-8");
            run(&[&["export", mbox], args].concat())
        }

        fn new() -> Self {
            let dir = TempDir::new().expect("a temporary directory is created");
            let mbox = dir.path().join("mail.mbox");
            fs::write(&mbox, MAILBOX).expect("the fixture mailbox is written");
            Self { dir, mbox }
        }

        /// A path inside the fixture directory.
        fn path(&self, name: &str) -> PathBuf {
            self.dir.path().join(name)
        }

        /// The string form of a path inside the fixture directory.
        fn target(&self, name: &str) -> String {
            self.path(name)
                .to_str()
                .expect("the fixture path is UTF-8")
                .to_owned()
        }
    }

    fn run(args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_mboxturbo"))
            .args(args)
            .env("NO_COLOR", "1")
            .output()
            .expect("the built mboxturbo binary runs")
    }

    fn code(output: &Output) -> i32 {
        output
            .status
            .code()
            .expect("the process exited rather than being signalled")
    }

    fn stderr(output: &Output) -> String {
        String::from_utf8_lossy(&output.stderr).into_owned()
    }

    fn stdout(output: &Output) -> String {
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    /// The `position` column of an export of positions and subjects, read back from Parquet.
    fn parquet_positions(path: &PathBuf) -> Vec<u64> {
        let file = File::open(path).expect("the parquet output exists");
        let reader = ParquetRecordBatchReaderBuilder::try_new(file)
            .expect("the output is a parquet file")
            .build()
            .expect("the parquet reader builds");
        let batches: Vec<RecordBatch> = reader
            .collect::<Result<_, _>>()
            .expect("every row group decodes");
        batches
            .iter()
            .flat_map(|batch| {
                batch
                    .column_by_name("position")
                    .expect("the position column was exported")
                    .as_primitive::<UInt64Type>()
                    .values()
                    .to_vec()
            })
            .collect()
    }

    /// The first record batch of a parquet file.
    fn first_parquet_batch(path: &Path) -> RecordBatch {
        let file = File::open(path).expect("the parquet output exists");
        ParquetRecordBatchReaderBuilder::try_new(file)
            .expect("the output is a parquet file")
            .build()
            .expect("the parquet reader builds")
            .next()
            .expect("the file holds a batch")
            .expect("the batch decodes")
    }

    /// The column names of a parquet file.
    fn parquet_field_names(file: File) -> Vec<String> {
        let builder =
            ParquetRecordBatchReaderBuilder::try_new(file).expect("the output is a parquet file");
        builder
            .schema()
            .fields()
            .iter()
            .map(|field| field.name().clone())
            .collect()
    }

    /// The sorted names of the entries of a directory.
    fn file_names(directory: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(directory)
            .expect("the output directory exists")
            .map(|entry| {
                entry
                    .expect("the entry is readable")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    fn export_positions(fixture: &Fixture, select: &[&str]) -> Vec<u64> {
        let target = fixture.target("out.parquet");
        let mut args = vec![
            "--format",
            "parquet",
            "-o",
            &target,
            "--columns",
            "position",
        ];
        args.extend_from_slice(select);
        let output = fixture.export(&args);
        assert_eq!(
            code(&output),
            0_i32,
            "the export succeeds: {}",
            stderr(&output)
        );
        parquet_positions(&fixture.path("out.parquet"))
    }

    #[test]
    fn parquet_holds_a_row_per_message_with_the_requested_columns() {
        let fixture = Fixture::new();
        let target = fixture.target("out.parquet");
        let output = fixture.export(&[
            "--format",
            "parquet",
            "-o",
            &target,
            "--columns",
            "position,subject",
        ]);
        assert_eq!(
            code(&output),
            0_i32,
            "parquet export succeeds: {}",
            stderr(&output)
        );
        let batch = first_parquet_batch(&fixture.path("out.parquet"));
        let subjects: Vec<_> = batch
            .column_by_name("subject")
            .expect("the subject column was exported")
            .as_string::<i32>()
            .iter()
            .collect();
        assert_eq!(
            subjects,
            [Some("zero"), Some("one"), Some("two"), Some("three")],
            "one subject per message, in mailbox order"
        );
    }

    #[test]
    fn parquet_holds_only_the_requested_columns() {
        let fixture = Fixture::new();
        let target = fixture.target("out.parquet");
        let output = fixture.export(&[
            "--format",
            "parquet",
            "-o",
            &target,
            "--columns",
            "position,subject",
        ]);
        assert_eq!(code(&output), 0_i32, "export succeeds: {}", stderr(&output));
        let file = File::open(fixture.path("out.parquet")).expect("the parquet output exists");
        assert_eq!(
            parquet_field_names(file),
            ["position", "subject"],
            "exactly the requested columns, none added"
        );
    }

    #[test]
    fn without_columns_the_library_defaults_are_written() {
        let fixture = Fixture::new();
        let target = fixture.target("out.parquet");
        let output = fixture.export(&["--format", "parquet", "-o", &target]);
        assert_eq!(
            code(&output),
            0_i32,
            "parquet export succeeds: {}",
            stderr(&output)
        );
        let file = File::open(fixture.path("out.parquet")).expect("the parquet output exists");
        let names = parquet_field_names(file);
        let expected: Vec<String> = Column::defaults()
            .iter()
            .map(|column| column.name().into_owned())
            .collect();
        assert_eq!(names, expected, "no --columns means Column::defaults()");
    }

    #[test]
    fn header_only_columns_export_without_body_columns() {
        // The core proves a header-only column list parses no body: pipeline.rs's
        // `depth_for` tests assert `Nothing` or `Headers`, never `Whole`, for such lists.
        let fixture = Fixture::new();
        let target = fixture.target("out.csv");
        let output = fixture.export(&[
            "--format",
            "csv",
            "-o",
            &target,
            "--columns",
            "subject,from",
        ]);
        assert_eq!(
            code(&output),
            0_i32,
            "csv export succeeds: {}",
            stderr(&output)
        );
        let text = fs::read_to_string(fixture.path("out.csv")).expect("the csv output exists");
        assert_eq!(
            text,
            "subject,from\r\nzero,\"[\"\"a@example.com\"\"]\"\r\n\
             one,\"[\"\"b@example.com\"\"]\"\r\ntwo,\"[\"\"c@example.com\"\"]\"\r\n\
             three,\"[\"\"d@example.com\"\"]\"\r\n",
            "the header and one row per message hold only the requested columns"
        );
    }

    #[test]
    fn a_body_column_exports_the_message_text() {
        let fixture = Fixture::new();
        let target = fixture.target("out.csv");
        let output = fixture.export(&["--format", "csv", "-o", &target, "--columns", "text"]);
        assert_eq!(
            code(&output),
            0_i32,
            "csv export succeeds: {}",
            stderr(&output)
        );
        let text = fs::read_to_string(fixture.path("out.csv")).expect("the csv output exists");
        assert!(text.contains("body two"), "the text column holds the body");
    }

    #[test]
    fn arrow_writes_a_readable_ipc_stream() {
        let fixture = Fixture::new();
        let target = fixture.target("out.arrow");
        let output = fixture.export(&["--format", "arrow", "-o", &target, "--columns", "position"]);
        assert_eq!(
            code(&output),
            0_i32,
            "arrow export succeeds: {}",
            stderr(&output)
        );
        let file = File::open(fixture.path("out.arrow")).expect("the arrow output exists");
        let rows: usize = StreamReader::try_new(file, None)
            .expect("the output is an IPC stream")
            .map(|batch| batch.expect("the batch decodes").num_rows())
            .sum();
        assert_eq!(rows, 4, "one row per message");
    }

    #[test]
    fn jsonl_writes_one_line_per_message() {
        let fixture = Fixture::new();
        let target = fixture.target("out.jsonl");
        let output = fixture.export(&["--format", "jsonl", "-o", &target, "--columns", "subject"]);
        assert_eq!(
            code(&output),
            0_i32,
            "jsonl export succeeds: {}",
            stderr(&output)
        );
        let text = fs::read_to_string(fixture.path("out.jsonl")).expect("the jsonl output exists");
        assert_eq!(text.lines().count(), 4, "one line per message");
        assert!(text.contains("three"), "the last subject is written");
    }

    #[test]
    fn csv_writes_a_header_and_a_row_per_message() {
        let fixture = Fixture::new();
        let target = fixture.target("out.csv");
        let output = fixture.export(&["--format", "csv", "-o", &target, "--columns", "position"]);
        assert_eq!(
            code(&output),
            0_i32,
            "csv export succeeds: {}",
            stderr(&output)
        );
        let text = fs::read_to_string(fixture.path("out.csv")).expect("the csv output exists");
        assert_eq!(
            text, "position\r\n0\r\n1\r\n2\r\n3\r\n",
            "header then positions"
        );
    }

    #[test]
    fn mbox_rewrites_the_selected_messages() {
        let fixture = Fixture::new();
        let target = fixture.target("out.mbox");
        let output = fixture.export(&["--format", "mbox", "-o", &target]);
        assert_eq!(
            code(&output),
            0_i32,
            "mbox export succeeds: {}",
            stderr(&output)
        );
        assert_eq!(
            fs::read_to_string(fixture.path("out.mbox")).expect("the mbox output exists"),
            MAILBOX,
            "exporting every message reproduces the mailbox"
        );
    }

    #[test]
    fn eml_writes_a_directory_with_a_file_per_message() {
        let fixture = Fixture::new();
        let target = fixture.target("emls");
        let output = fixture.export(&["--format", "eml", "-o", &target]);
        assert_eq!(
            code(&output),
            0_i32,
            "eml export succeeds: {}",
            stderr(&output)
        );
        assert_eq!(
            file_names(&fixture.path("emls")),
            ["0.eml", "1.eml", "2.eml", "3.eml", "manifest.jsonl"],
            "one file per message, plus the sink's manifest"
        );
        let second = fs::read_to_string(fixture.path("emls").join("2.eml"))
            .expect("the third message was written as a file");
        assert!(
            second.contains("Subject: two"),
            "each file holds its own message"
        );
    }

    #[test]
    fn eml_manifest_fills_message_id_and_date() {
        let fixture = Fixture::new();
        let mbox = concat!(
            "From a@example.com Mon Jan  1 00:00:00 2024\n",
            "Message-ID: <m1@example.com>\n",
            "Date: Mon, 1 Jan 2024 00:00:00 +0000\n",
            "Subject: one\n\nbody\n\n",
        );
        fs::write(&fixture.mbox, mbox).expect("the mailbox is rewritten");
        let target = fixture.target("emls");
        let output = fixture.export(&["--format", "eml", "-o", &target]);
        assert_eq!(code(&output), 0_i32, "eml export: {}", stderr(&output));
        let manifest = fs::read_to_string(fixture.path("emls").join("manifest.jsonl"))
            .expect("the manifest exists");
        assert!(
            manifest.contains("m1@example.com") && manifest.contains("2024-01-01"),
            "the manifest names the message id and date: {manifest}"
        );
    }

    #[test]
    fn columns_with_eml_or_mbox_exit_64() {
        let fixture = Fixture::new();
        for format in ["eml", "mbox"] {
            let target = fixture.target(&format!("out-{format}"));
            let output = fixture.export(&["--format", format, "-o", &target, "--columns", "raw"]);
            assert_eq!(code(&output), 64_i32, "--columns with {format} is usage");
            assert_eq!(stderr(&output).lines().count(), 1, "one line on stderr");
        }
    }

    #[test]
    fn an_empty_select_file_exits_64_naming_it() {
        let fixture = Fixture::new();
        let target = fixture.target("out.csv");
        let empty = fixture.target("empty.txt");
        fs::write(&empty, "\n  \n").expect("the select file is written");
        let output = fixture.export(&["--format", "csv", "-o", &target, "--select-file", &empty]);
        assert_eq!(code(&output), 64_i32, "an empty select file is usage");
        assert!(
            stderr(&output).contains("empty.txt")
                && stderr(&output).contains("selects no messages"),
            "the message names the file: {}",
            stderr(&output)
        );
    }

    #[test]
    fn an_index_under_a_missing_directory_exits_74() {
        let fixture = Fixture::new();
        let target = fixture.target("out.csv");
        let index = fixture.target("no/such/dir/mail.idx");
        let output = fixture.export(&["--format", "csv", "-o", &target, "--index", &index]);
        assert_eq!(
            code(&output),
            74_i32,
            "a missing index directory is I/O, not a missing mailbox: {}",
            stderr(&output)
        );
    }

    #[test]
    fn select_ranges_and_positions_are_united_without_duplicates() {
        let fixture = Fixture::new();
        assert_eq!(
            export_positions(&fixture, &["--select", "2..4", "--select", "1..3,2"]),
            [1, 2, 3],
            "overlapping ranges and a repeated position collapse to ascending positions"
        );
    }

    #[test]
    fn select_file_lines_are_specs_and_blank_lines_are_ignored() {
        let fixture = Fixture::new();
        fs::write(fixture.path("picks.txt"), "3\n\n  \n0..2\n")
            .expect("the select file is written");
        let picks = fixture.target("picks.txt");
        assert_eq!(
            export_positions(&fixture, &["--select-file", &picks]),
            [0, 1, 3],
            "each line is a spec and the union is ascending"
        );
    }

    #[test]
    fn select_and_select_file_are_united() {
        let fixture = Fixture::new();
        fs::write(fixture.path("picks.txt"), "0\n").expect("the select file is written");
        let picks = fixture.target("picks.txt");
        assert_eq!(
            export_positions(&fixture, &["--select", "2", "--select-file", &picks]),
            [0, 2],
            "both sources contribute"
        );
    }

    #[test]
    fn a_malformed_spec_exits_64_naming_it() {
        let fixture = Fixture::new();
        let target = fixture.target("out.csv");
        let output = fixture.export(&["--format", "csv", "-o", &target, "--select", "3..1"]);
        assert_eq!(code(&output), 64_i32, "a bad spec is a usage error");
        assert!(
            stderr(&output).contains("3..1"),
            "the message names the spec"
        );
        assert_eq!(stderr(&output).lines().count(), 1, "one line on stderr");
        assert!(!fixture.path("out.csv").exists(), "nothing is written");
    }

    #[test]
    fn a_malformed_select_file_line_exits_64() {
        let fixture = Fixture::new();
        fs::write(fixture.path("picks.txt"), "0\nx\n").expect("the select file is written");
        let picks = fixture.target("picks.txt");
        let target = fixture.target("out.csv");
        let output = fixture.export(&["--format", "csv", "-o", &target, "--select-file", &picks]);
        assert_eq!(code(&output), 64_i32, "a bad line is a usage error");
        assert!(stderr(&output).contains('x'), "the message names the spec");
    }

    #[test]
    fn a_position_past_the_last_message_exits_64_naming_it() {
        let fixture = Fixture::new();
        let target = fixture.target("out.csv");
        let output = fixture.export(&["--format", "csv", "-o", &target, "--select", "1,4"]);
        assert_eq!(
            code(&output),
            64_i32,
            "position 4 does not exist in 4 messages"
        );
        assert!(
            stderr(&output).contains("position 4"),
            "the message names the position"
        );
        assert_eq!(stderr(&output).lines().count(), 1, "one line on stderr");
        assert!(!fixture.path("out.csv").exists(), "nothing is written");
    }

    #[test]
    fn an_unknown_column_exits_64_naming_it() {
        let fixture = Fixture::new();
        let target = fixture.target("out.csv");
        let output = fixture.export(&[
            "--format",
            "csv",
            "-o",
            &target,
            "--columns",
            "subject,bogus_column",
        ]);
        assert_eq!(code(&output), 64_i32, "an unknown column is a usage error");
        assert!(
            stderr(&output).contains("bogus_column"),
            "the message names the column"
        );
    }

    #[test]
    fn an_existing_output_is_refused_and_left_unchanged() {
        let fixture = Fixture::new();
        fs::write(fixture.path("out.csv"), "keep me").expect("the existing output is written");
        let target = fixture.target("out.csv");
        let output = fixture.export(&["--format", "csv", "-o", &target, "--quiet"]);
        assert_eq!(
            code(&output),
            73_i32,
            "an existing target without --overwrite is 73"
        );
        assert_eq!(
            fs::read_to_string(fixture.path("out.csv")).expect("the output is still there"),
            "keep me",
            "the existing file is untouched"
        );
        assert_eq!(stderr(&output).lines().count(), 1, "one line on stderr");
    }

    #[test]
    fn overwrite_replaces_an_existing_output() {
        let fixture = Fixture::new();
        fs::write(fixture.path("out.csv"), "old").expect("the existing output is written");
        let target = fixture.target("out.csv");
        let output = fixture.export(&[
            "--format",
            "csv",
            "-o",
            &target,
            "--columns",
            "position",
            "--overwrite",
        ]);
        assert_eq!(
            code(&output),
            0_i32,
            "--overwrite allows it: {}",
            stderr(&output)
        );
        assert_eq!(
            fs::read_to_string(fixture.path("out.csv")).expect("the output exists"),
            "position\r\n0\r\n1\r\n2\r\n3\r\n",
            "the new export replaced the old file"
        );
    }

    #[test]
    fn a_missing_mailbox_exits_66() {
        let fixture = Fixture::new();
        let target = fixture.target("out.csv");
        let missing = fixture.target("absent.mbox");
        let output = run(&["export", &missing, "--format", "csv", "-o", &target]);
        assert_eq!(code(&output), 66_i32, "a mailbox that does not exist is 66");
        assert_eq!(stderr(&output).lines().count(), 1, "one line on stderr");
    }

    #[test]
    fn a_missing_output_directory_exits_74_not_66() {
        let fixture = Fixture::new();
        let target = fixture.target("no/such/dir/out.csv");
        let output = fixture.export(&["--format", "csv", "-o", &target]);
        assert_eq!(
            code(&output),
            74_i32,
            "NotFound after the mailbox is open is I/O, not 66"
        );
    }

    #[test]
    fn a_missing_select_file_exits_74() {
        let fixture = Fixture::new();
        let target = fixture.target("out.csv");
        let missing = fixture.target("absent.txt");
        let output = fixture.export(&["--format", "csv", "-o", &target, "--select-file", &missing]);
        assert_eq!(
            code(&output),
            74_i32,
            "an unreadable select file is an I/O error"
        );
    }

    #[test]
    fn a_corrupt_index_exits_65() {
        let fixture = Fixture::new();
        let index = fixture.target("mail.idx");
        let first = fixture.target("first.csv");
        let build = fixture.export(&["--format", "csv", "-o", &first, "--index", &index]);
        assert_eq!(
            code(&build),
            0_i32,
            "the index is built: {}",
            stderr(&build)
        );
        let mut damaged = fs::read(&index).expect("the index file was written");
        damaged[60] ^= 0xFF;
        fs::write(&index, &damaged).expect("the index file is damaged");
        let second = fixture.target("second.csv");
        let output = fixture.export(&["--format", "csv", "-o", &second, "--index", &index]);
        assert_eq!(
            code(&output),
            65_i32,
            "a flipped byte makes the index corrupt"
        );
        assert_eq!(stderr(&output).lines().count(), 1, "one line on stderr");
        assert!(!fixture.path("second.csv").exists(), "nothing is written");
    }

    #[test]
    fn csv_to_stdout_writes_only_the_export() {
        let fixture = Fixture::new();
        let output = fixture.export(&[
            "--format",
            "csv",
            "-o",
            "-",
            "--columns",
            "position",
            "--quiet",
        ]);
        assert_eq!(
            code(&output),
            0_i32,
            "csv to stdout succeeds: {}",
            stderr(&output)
        );
        assert_eq!(
            stdout(&output),
            "position\r\n0\r\n1\r\n2\r\n3\r\n",
            "stdout holds exactly the csv"
        );
        assert!(output.stderr.is_empty(), "nothing is printed on stderr");
    }

    #[test]
    fn arrow_to_stdout_is_a_readable_ipc_stream() {
        let fixture = Fixture::new();
        let output = fixture.export(&["--format", "arrow", "-o", "-", "--select", "1..3"]);
        assert_eq!(
            code(&output),
            0_i32,
            "arrow to stdout succeeds: {}",
            stderr(&output)
        );
        let rows: usize = StreamReader::try_new(Cursor::new(output.stdout), None)
            .expect("stdout is an IPC stream")
            .map(|batch| batch.expect("the batch decodes").num_rows())
            .sum();
        assert_eq!(rows, 2, "only the selected messages are streamed");
    }

    #[test]
    fn jsonl_and_mbox_stream_to_stdout() {
        let fixture = Fixture::new();
        let jsonl = fixture.export(&["--format", "jsonl", "-o", "-", "--columns", "position"]);
        assert_eq!(
            code(&jsonl),
            0_i32,
            "jsonl to stdout succeeds: {}",
            stderr(&jsonl)
        );
        assert_eq!(
            stdout(&jsonl).lines().count(),
            4,
            "one jsonl line per message"
        );
        let mbox = fixture.export(&["--format", "mbox", "-o", "-"]);
        assert_eq!(
            code(&mbox),
            0_i32,
            "mbox to stdout succeeds: {}",
            stderr(&mbox)
        );
        assert_eq!(stdout(&mbox), MAILBOX, "stdout holds the mailbox");
    }

    #[test]
    fn parquet_and_eml_cannot_go_to_stdout() {
        let fixture = Fixture::new();
        for format in ["parquet", "eml"] {
            let output = fixture.export(&["--format", format, "-o", "-"]);
            assert_eq!(code(&output), 64_i32, "{format} to stdout is a usage error");
            assert!(
                output.stdout.is_empty(),
                "{format} writes nothing to stdout"
            );
            assert_eq!(stderr(&output).lines().count(), 1, "one line on stderr");
        }
    }
}
