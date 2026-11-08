//! End-to-end behaviour of `Mailbox` and `Message` against a small hand-written mbox.

#[cfg(test)]
mod mailbox {
    use std::fs;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::PathBuf;

    use mboxturbo::{Corruption, Mailbox, MboxturboError, Message};
    use rayon::prelude::*;
    use tempfile::TempDir;

    const PLAIN: &str = "From jane@example.com Mon Jan  1 00:00:00 2024\n\
From: Jane Doe <jane@example.com>\n\
To: a@example.org, B <b@example.org>\n\
Cc: c@example.org\n\
Subject: =?utf-8?q?caf=C3=A9?=\n\
Date: Mon, 01 Jan 2024 00:00:00 -0500\n\
Message-ID: <one@example.com>\n\
Received: from mx1.example.com\n\tby mail.example.org; Mon, 1 Jan 2024\n\
Received: from mx2.example.com by mx1.example.com\n\
\n\
first body\n\
>From the escaped line\n\
\n";

    const MULTIPART: &str = "From bob@example.com Tue Jan  2 00:00:00 2024\n\
From: bob@example.com\n\
Subject: report\n\
MIME-Version: 1.0\n\
Content-Type: multipart/mixed; boundary=\"B\"\n\
\n\
--B\n\
Content-Type: text/html\n\
\n\
<p>hello</p>\n\
--B\n\
Content-Type: application/octet-stream; name=\"x.bin\"\n\
Content-Disposition: attachment; filename=\"x.bin\"\n\
Content-Transfer-Encoding: base64\n\
\n\
AAEC\n\
--B--\n\
\n";

    const BARE: &str = "From nobody Wed Jan  3 00:00:00 2024\nSubject: third\n\nbody\n";

    struct Fixture {
        _directory: TempDir,
        index: PathBuf,
        mbox: PathBuf,
    }

    impl Fixture {
        fn append(&self, message: &str) {
            let mut contents = fs::read(&self.mbox).expect("fixture mbox is readable");
            contents.extend_from_slice(message.as_bytes());
            fs::write(&self.mbox, contents).expect("fixture mbox is rewritten with the append");
        }

        fn cached(&self) -> Mailbox {
            Mailbox::open_cached(&self.mbox, &self.index).expect("fixture mbox opens with a cache")
        }

        fn mailbox(&self) -> Mailbox {
            Mailbox::open(&self.mbox).expect("fixture mbox opens")
        }

        fn message(&self, position: usize) -> Message {
            self.mailbox()
                .message(position)
                .expect("fixture message exists at that position")
        }

        fn new() -> Self {
            let directory = tempfile::tempdir().expect("temporary directory is created");
            let mbox = directory.path().join("inbox.mbox");
            let index = directory.path().join("inbox.mbxidx");
            fs::write(&mbox, [PLAIN, MULTIPART, BARE].concat()).expect("fixture mbox is written");
            Self {
                _directory: directory,
                mbox,
                index,
            }
        }
    }

    #[test]
    fn an_escaped_from_line_does_not_start_a_message() {
        let mailbox = Fixture::new().mailbox();
        assert_eq!(mailbox.len(), 3, "three separators, one escaped body line");
    }

    #[test]
    fn the_first_message_is_returned_byte_exact() {
        let mailbox = Fixture::new().mailbox();
        assert_eq!(
            mailbox.raw(0),
            Some(PLAIN.as_bytes()),
            "first message is byte-exact"
        );
    }

    #[test]
    fn the_last_message_runs_to_eof() {
        let mailbox = Fixture::new().mailbox();
        assert_eq!(
            mailbox.raw(2),
            Some(BARE.as_bytes()),
            "last message runs to EOF"
        );
    }

    #[test]
    fn a_position_past_the_end_has_no_raw_message() {
        let mailbox = Fixture::new().mailbox();
        assert_eq!(mailbox.raw(3), None, "only positions 0..3 exist");
    }

    #[test]
    fn sequential_and_parallel_iteration_agree() {
        let mailbox = Fixture::new().mailbox();
        let sequential: Vec<&[u8]> = mailbox.iter().collect();
        let parallel: Vec<&[u8]> = mailbox.par_iter().collect();
        assert_eq!(sequential.len(), 3, "iteration visits every message");
        assert_eq!(sequential, parallel, "same messages in the same order");
    }

    #[test]
    fn iteration_is_double_ended() {
        let mailbox = Fixture::new().mailbox();
        assert_eq!(
            mailbox.iter().next_back(),
            Some(BARE.as_bytes()),
            "the back of the iterator is the last message"
        );
    }

    #[test]
    fn an_encoded_word_subject_is_decoded() {
        let message = Fixture::new().message(0);
        assert_eq!(
            message.subject(),
            Some("caf\u{e9}"),
            "RFC 2047 q-encoding is decoded"
        );
    }

    #[test]
    fn the_message_id_has_its_angle_brackets_stripped() {
        let message = Fixture::new().message(0);
        assert_eq!(
            message.message_id(),
            Some("one@example.com"),
            "brackets stripped"
        );
    }

    #[test]
    fn the_from_header_is_not_confused_with_the_mbox_separator() {
        let message = Fixture::new().message(0);
        assert_eq!(
            message.header("from").as_deref(),
            Some("Jane Doe <jane@example.com>"),
            "the From: header, not the mbox separator"
        );
    }

    #[test]
    fn the_from_address_keeps_its_display_name() {
        let message = Fixture::new().message(0);
        let from: Vec<_> = message
            .from()
            .map(|address| (address.name, address.email))
            .collect();
        assert_eq!(
            from,
            vec![(Some("Jane Doe"), Some("jane@example.com"))],
            "display name kept"
        );
    }

    #[test]
    fn every_to_address_is_listed() {
        let message = Fixture::new().message(0);
        let to: Vec<_> = message.to().filter_map(|address| address.email).collect();
        assert_eq!(
            to,
            vec!["a@example.org", "b@example.org"],
            "every To: address"
        );
    }

    #[test]
    fn the_cc_address_is_parsed() {
        let message = Fixture::new().message(0);
        let cc: Vec<_> = message.cc().filter_map(|address| address.email).collect();
        assert_eq!(cc, vec!["c@example.org"], "the single Cc: address");
    }

    #[test]
    fn every_received_header_is_returned_in_file_order_unfolded() {
        let message = Fixture::new().message(0);
        let received: Vec<_> = message.header_values("RECEIVED").collect();
        assert_eq!(
            received,
            vec![
                "from mx1.example.com\tby mail.example.org; Mon, 1 Jan 2024",
                "from mx2.example.com by mx1.example.com",
            ],
            "first value first, continuation line joined"
        );
    }

    #[test]
    fn the_date_resolves_to_utc_and_keeps_its_offset() {
        let message = Fixture::new().message(0);
        assert_eq!(
            message
                .date()
                .map(|stamp| (stamp.unix_seconds, stamp.offset_minutes)),
            Some((1_704_085_200_i64, -300_i32)),
            "midnight at -0500 is 05:00 UTC"
        );
    }

    #[test]
    fn a_multipart_message_has_one_attachment() {
        let message = Fixture::new().message(1);
        assert_eq!(
            message.attachments().count(),
            1,
            "only the octet-stream part is an attachment"
        );
    }

    #[test]
    fn an_attachment_keeps_its_filename() {
        let message = Fixture::new().message(1);
        let filenames: Vec<_> = message
            .attachments()
            .map(|attachment| attachment.filename)
            .collect();
        assert_eq!(
            filenames,
            vec![Some("x.bin")],
            "filename from Content-Disposition"
        );
    }

    #[test]
    fn an_attachment_reports_its_media_type() {
        let message = Fixture::new().message(1);
        let types: Vec<_> = message
            .attachments()
            .map(|attachment| attachment.content_type())
            .collect();
        assert_eq!(
            types,
            vec![Some("application/octet-stream".to_owned())],
            "media type of the attachment part"
        );
    }

    #[test]
    fn an_attachment_body_is_base64_decoded() {
        let message = Fixture::new().message(1);
        let data: Vec<Vec<u8>> = message
            .attachments()
            .map(|attachment| attachment.data.to_vec())
            .collect();
        assert_eq!(data, vec![vec![0_u8, 1, 2]], "AAEC decodes to three bytes");
    }

    #[test]
    fn an_html_part_is_listed_as_an_html_body() {
        let message = Fixture::new().message(1);
        let html: Vec<_> = message.html_bodies().collect();
        assert_eq!(
            html.len(),
            1,
            "the multipart message has one text/html part"
        );
        assert!(
            html[0].contains("<p>hello</p>"),
            "the html body holds the part's markup"
        );
    }

    #[test]
    fn messages_outlive_the_mailbox_they_came_from() {
        let message = Fixture::new().message(2);
        assert_eq!(
            message.subject(),
            Some("third"),
            "mapping kept alive by the message"
        );
    }

    #[test]
    fn a_parsed_batch_is_clamped_to_the_mailbox_and_kept_in_order() {
        let mailbox = Fixture::new().mailbox();
        let batch = mailbox.parse_batch(1..99);
        let subjects: Vec<_> = batch
            .messages
            .par_iter()
            .map(|message| message.subject())
            .collect();
        assert_eq!(
            subjects,
            vec![Some("report"), Some("third")],
            "clamped and ordered"
        );
    }

    #[test]
    fn an_empty_file_is_an_empty_mailbox() {
        let fixture = Fixture::new();
        fs::write(&fixture.mbox, b"").expect("fixture mbox is truncated");
        let mailbox = fixture.mailbox();
        assert!(mailbox.is_empty(), "no messages");
        assert_eq!(mailbox.iter().count(), 0, "nothing to iterate");
    }

    #[test]
    fn a_missing_cache_is_built_and_written() {
        let fixture = Fixture::new();
        let mailbox = fixture.cached();
        let written = fs::read(&fixture.index).expect("cache file is written");
        assert_eq!(mailbox.len(), 3, "the cache build indexes every message");
        assert!(!written.is_empty(), "the cache file has content");
    }

    #[test]
    fn a_valid_cache_is_reused_without_being_rewritten() {
        let fixture = Fixture::new();
        let first = fixture.cached();
        let inode = fs::metadata(&fixture.index)
            .expect("cache file is written")
            .ino();
        let second = fixture.cached();
        assert_eq!(first.len(), 3, "the cache build indexes every message");
        assert_eq!(first.index(), second.index(), "same index");
        assert_eq!(
            fs::metadata(&fixture.index)
                .expect("cache file is still present")
                .ino(),
            inode,
            "a save renames a new temp file over the cache, so an unchanged inode means no rewrite"
        );
    }

    #[test]
    fn a_stale_cache_is_rebuilt_and_rewritten() {
        let fixture = Fixture::new();
        let built = fixture.cached();
        assert_eq!(built.len(), 3, "initial cache indexes the fixture messages");
        let before = fs::read(&fixture.index).expect("cache file is written");
        fixture.append(BARE);
        let mailbox = fixture.cached();
        assert_eq!(mailbox.len(), 4, "new message indexed");
        assert_ne!(
            fs::read(&fixture.index).expect("cache file is still readable"),
            before,
            "the stale cache file was rewritten"
        );
        let reloaded = fixture.cached();
        assert_eq!(reloaded.index(), mailbox.index(), "rewritten cache matches");
    }

    #[test]
    fn a_corrupt_cache_is_reported_as_a_checksum_failure() {
        let fixture = Fixture::new();
        let built = fixture.cached();
        assert_eq!(built.len(), 3, "initial cache indexes the fixture messages");
        let mut damaged = fs::read(&fixture.index).expect("cache file is written");
        damaged[60] ^= 0xFF;
        fs::write(&fixture.index, &damaged).expect("cache file is damaged");
        let error = Mailbox::open_cached(&fixture.mbox, &fixture.index)
            .expect_err("a damaged cache is rejected");
        assert!(
            matches!(
                error,
                MboxturboError::CorruptIndex {
                    corruption: Corruption::Checksum,
                    ..
                }
            ),
            "a flipped byte fails the checksum"
        );
    }

    #[test]
    fn a_corrupt_cache_is_left_in_place() {
        let fixture = Fixture::new();
        drop(fixture.cached());
        let mut damaged = fs::read(&fixture.index).expect("cache file is written");
        damaged[60] ^= 0xFF;
        fs::write(&fixture.index, &damaged).expect("cache file is damaged");
        let error = Mailbox::open_cached(&fixture.mbox, &fixture.index)
            .expect_err("a damaged cache is rejected");
        assert!(
            matches!(error, MboxturboError::CorruptIndex { .. }),
            "the damaged cache is reported, not repaired"
        );
        assert_eq!(
            fs::read(&fixture.index).expect("cache file is still readable"),
            damaged,
            "evidence preserved"
        );
    }

    #[test]
    fn a_missing_mailbox_is_an_io_error_naming_the_path() {
        let fixture = Fixture::new();
        let missing = fixture.mbox.with_extension("absent");
        let error = Mailbox::open(&missing).expect_err("a missing mbox is rejected");
        assert!(
            matches!(&error, MboxturboError::Io { path, .. } if *path == missing),
            "the error carries the missing path"
        );
    }
}
