//! End-to-end behaviour of `Mailbox` and `Message` against a small hand-written mbox.

#[cfg(test)]
mod mailbox {
    use std::fs;
    use std::path::PathBuf;

    use mboxturbo::{Corruption, Mailbox, MboxturboError};
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
        mbox: PathBuf,
        index: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("tempdir");
            let mbox = directory.path().join("inbox.mbox");
            let index = directory.path().join("inbox.mbxidx");
            fs::write(&mbox, [PLAIN, MULTIPART, BARE].concat()).expect("write mbox");
            Self {
                _directory: directory,
                mbox,
                index,
            }
        }

        fn append(&self, message: &str) {
            let mut contents = fs::read(&self.mbox).expect("read mbox");
            contents.extend_from_slice(message.as_bytes());
            fs::write(&self.mbox, contents).expect("rewrite mbox");
        }
    }

    #[test]
    fn indexes_every_message_and_ignores_escaped_from_lines() {
        let fixture = Fixture::new();
        let mailbox = Mailbox::open(&fixture.mbox).expect("open");
        assert_eq!(mailbox.len(), 3, "three separators, one escaped body line");
        assert_eq!(
            mailbox.raw(0),
            Some(PLAIN.as_bytes()),
            "first message is byte-exact"
        );
        assert_eq!(
            mailbox.raw(2),
            Some(BARE.as_bytes()),
            "last message runs to EOF"
        );
        assert_eq!(mailbox.raw(3), None, "past the end");
    }

    #[test]
    fn sequential_and_parallel_iteration_agree() {
        let fixture = Fixture::new();
        let mailbox = Mailbox::open(&fixture.mbox).expect("open");
        let sequential: Vec<&[u8]> = mailbox.iter().collect();
        let parallel: Vec<&[u8]> = mailbox.par_iter().collect();
        assert_eq!(sequential, parallel, "same messages in the same order");
        assert_eq!(
            mailbox.iter().next_back(),
            Some(BARE.as_bytes()),
            "double-ended"
        );
    }

    #[test]
    fn parses_headers_without_mistaking_the_separator_for_one() {
        let fixture = Fixture::new();
        let message = Mailbox::open(&fixture.mbox)
            .expect("open")
            .message(0)
            .expect("first");
        assert_eq!(message.subject(), Some("caf\u{e9}"), "encoded word decoded");
        assert_eq!(
            message.message_id(),
            Some("one@example.com"),
            "brackets stripped"
        );
        assert_eq!(
            message.header("from").as_deref(),
            Some("Jane Doe <jane@example.com>"),
            "the From: header, not the mbox separator"
        );
        let from: Vec<_> = message
            .from()
            .map(|address| (address.name, address.email))
            .collect();
        assert_eq!(
            from,
            vec![(Some("Jane Doe"), Some("jane@example.com"))],
            "display name kept"
        );
        let to: Vec<_> = message.to().filter_map(|address| address.email).collect();
        assert_eq!(
            to,
            vec!["a@example.org", "b@example.org"],
            "every To: address"
        );
        assert_eq!(message.cc().count(), 1, "Cc: parsed");
    }

    #[test]
    fn returns_every_received_header_in_file_order_unfolded() {
        let fixture = Fixture::new();
        let message = Mailbox::open(&fixture.mbox)
            .expect("open")
            .message(0)
            .expect("first");
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
    fn resolves_the_date_and_keeps_its_offset() {
        let fixture = Fixture::new();
        let message = Mailbox::open(&fixture.mbox)
            .expect("open")
            .message(0)
            .expect("first");
        assert_eq!(
            message
                .date()
                .map(|stamp| (stamp.unix_seconds, stamp.offset_minutes)),
            Some((1_704_085_200, -300)),
            "midnight at -0500 is 05:00 UTC"
        );
    }

    #[test]
    fn decodes_attachments_and_html_bodies() {
        let fixture = Fixture::new();
        let message = Mailbox::open(&fixture.mbox)
            .expect("open")
            .message(1)
            .expect("second");
        let attachments: Vec<_> = message.attachments().collect();
        assert_eq!(attachments.len(), 1, "one attachment");
        assert_eq!(attachments[0].filename, Some("x.bin"), "filename");
        assert_eq!(
            attachments[0].content_type().as_deref(),
            Some("application/octet-stream"),
            "media type"
        );
        assert_eq!(*attachments[0].data, [0, 1, 2], "base64 removed");
        let html: Vec<_> = message.html_bodies().collect();
        assert!(html[0].contains("<p>hello</p>"), "html body");
    }

    #[test]
    fn messages_outlive_the_mailbox_they_came_from() {
        let fixture = Fixture::new();
        let message = Mailbox::open(&fixture.mbox)
            .expect("open")
            .message(2)
            .expect("third");
        assert_eq!(
            message.subject(),
            Some("third"),
            "mapping kept alive by the message"
        );
    }

    #[test]
    fn parses_batches_in_parallel_and_in_order() {
        let fixture = Fixture::new();
        let mailbox = Mailbox::open(&fixture.mbox).expect("open");
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
        fs::write(&fixture.mbox, b"").expect("truncate");
        let mailbox = Mailbox::open(&fixture.mbox).expect("open");
        assert!(mailbox.is_empty(), "no messages");
        assert_eq!(mailbox.iter().count(), 0, "nothing to iterate");
    }

    #[test]
    fn a_missing_cache_is_built_and_then_reused() {
        let fixture = Fixture::new();
        let first = Mailbox::open_cached(&fixture.mbox, &fixture.index).expect("build");
        let written = fs::read(&fixture.index).expect("cache written");
        let second = Mailbox::open_cached(&fixture.mbox, &fixture.index).expect("reuse");
        assert_eq!(first.index(), second.index(), "same index");
        assert_eq!(
            fs::read(&fixture.index).expect("cache"),
            written,
            "cache not rewritten"
        );
    }

    #[test]
    fn a_stale_cache_is_rebuilt_and_rewritten() {
        let fixture = Fixture::new();
        let built = Mailbox::open_cached(&fixture.mbox, &fixture.index).expect("build");
        assert_eq!(built.len(), 3, "initial cache indexes the fixture messages");
        fixture.append(BARE);
        let mailbox = Mailbox::open_cached(&fixture.mbox, &fixture.index).expect("rebuild");
        assert_eq!(mailbox.len(), 4, "new message indexed");
        let reloaded = Mailbox::open_cached(&fixture.mbox, &fixture.index).expect("reuse");
        assert_eq!(reloaded.index(), mailbox.index(), "rewritten cache matches");
    }

    #[test]
    fn a_corrupt_cache_is_reported_and_left_in_place() {
        let fixture = Fixture::new();
        let built = Mailbox::open_cached(&fixture.mbox, &fixture.index).expect("build");
        assert_eq!(built.len(), 3, "initial cache indexes the fixture messages");
        let mut damaged = fs::read(&fixture.index).expect("cache");
        damaged[60] ^= 0xFF;
        fs::write(&fixture.index, &damaged).expect("damage cache");
        let error = Mailbox::open_cached(&fixture.mbox, &fixture.index).expect_err("corrupt");
        assert!(
            matches!(
                error,
                MboxturboError::CorruptIndex {
                    corruption: Corruption::Checksum,
                    ..
                }
            ),
            "checksum failure surfaces: {error}"
        );
        assert_eq!(
            fs::read(&fixture.index).expect("cache"),
            damaged,
            "evidence preserved"
        );
    }

    #[test]
    fn a_missing_mailbox_is_an_io_error_naming_the_path() {
        let fixture = Fixture::new();
        let missing = fixture.mbox.with_extension("absent");
        let error = Mailbox::open(&missing).expect_err("missing");
        assert!(
            matches!(&error, MboxturboError::Io { path, .. } if *path == missing),
            "path kept"
        );
    }
}
