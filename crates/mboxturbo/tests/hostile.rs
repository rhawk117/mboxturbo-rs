//! Hostile and malformed messages: every accessor must answer without panicking.

#[cfg(test)]
mod hostile {
    use std::fs;
    use std::hint::black_box;

    use mboxturbo::{Mailbox, Message, Timestamp};
    use proptest::prelude::*;
    use tempfile::TempDir;

    fn open(contents: &[u8]) -> (TempDir, Mailbox) {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("hostile.mbox");
        fs::write(&path, contents).expect("write mbox");
        let mailbox = Mailbox::open(&path).expect("open");
        (directory, mailbox)
    }

    fn exercise(message: &Message) {
        let _envelope = black_box((message.subject(), message.message_id(), message.date()));
        let _headers = black_box((
            message.header("received"),
            message.header_values("x.trace").count(),
        ));
        let _addresses = black_box(
            message
                .from()
                .chain(message.to())
                .chain(message.cc())
                .count(),
        );
        let _bodies = black_box(message.text_bodies().chain(message.html_bodies()).count());
        let _attachments = message
            .attachments()
            .map(|attachment| black_box((attachment.data.len(), attachment.content_type().is_some())))
            .count();
        let _raw = black_box(message.raw());
    }

    fn only_message(contents: &[u8]) -> (TempDir, Message) {
        let (directory, mailbox) = open(contents);
        let message = mailbox.message(0).expect("one message");
        (directory, message)
    }

    #[test]
    fn a_received_header_whose_folded_line_is_blank_still_parses() {
        for contents in [
            &b"From a\nSubject: s\nReceived:\n\t"[..],
            b"From a\nSubject: s\nReceived: from x;\n\t",
        ] {
            let (_directory, message) = only_message(contents);
            assert_eq!(
                message.subject(),
                Some("s"),
                "mail-parser 0.11.2 panicked here"
            );
            exercise(&message);
        }
    }

    #[test]
    fn a_nested_message_without_headers_has_readable_attachment_bytes() {
        let (_directory, message) =
            only_message(b"From a\nContent-Type: message/rfc822\n\nno headers here\n");
        exercise(&message);
        assert!(
            message
                .attachments()
                .all(|attachment| attachment.data.len() <= message.raw().len()),
            "attachment bytes come from inside the message"
        );
    }

    #[test]
    fn zones_past_twelve_hours_keep_their_offset_and_instant() {
        let (_directory, message) = only_message(
            b"From a\nDate: Mon, 01 Jan 2024 12:00:00 +1300 (NZDT)\nSubject: s\n\nbody\n",
        );
        assert_eq!(
            message.date(),
            Some(Timestamp {
                unix_seconds: 1_704_063_600,
                offset_minutes: 780
            }),
            "12:00 at +1300 is 23:00 UTC the day before"
        );
    }

    #[test]
    fn header_names_with_dots_are_found() {
        let (_directory, message) = only_message(b"From a\nX.Trace: route\nSubject: s\n\nbody\n");
        assert_eq!(
            message.header("x.trace").as_deref(),
            Some("route"),
            "dotted name"
        );
    }

    fn hostile_fragments() -> impl Strategy<Value = Vec<u8>> {
        let fragment = prop_oneof![
            Just(b"From a@example.com Mon Jan  1 00:00:00 2024\n".to_vec()),
            Just(b"Received:\n\t".to_vec()),
            Just(b"Received: from x;\n\t".to_vec()),
            Just(b"Received: from a by b; Mon, 1 Jan 2024 00:00:00 +0000\n".to_vec()),
            Just(b"Content-Type: message/rfc822\n".to_vec()),
            Just(b"Content-Type: multipart/mixed; boundary=\"B\"\n".to_vec()),
            Just(b"Content-Transfer-Encoding: base64\n".to_vec()),
            Just(b"Content-Disposition: attachment; filename=\"a.bin\"\n".to_vec()),
            Just(b"--B\n".to_vec()),
            Just(b"--B--\n".to_vec()),
            Just(b"Subject: =?utf-8?b?Y2Fmw6k=?=\n".to_vec()),
            Just(b"Date: Mon, 01 Jan 2024 12:00:00 +1400\n".to_vec()),
            Just(b"From: \"A\" <a@example.com>, group: b@x, c@y;\n".to_vec()),
            Just(b"X.Trace: route\n".to_vec()),
            Just(b"\n".to_vec()),
            Just(b"\t".to_vec()),
            Just(b"AAEC\n".to_vec()),
            proptest::collection::vec(any::<u8>(), 0..12),
        ];
        proptest::collection::vec(fragment, 0..32).prop_map(|parts| parts.concat())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn every_accessor_answers_on_any_input(contents in hostile_fragments()) {
            let (_directory, mailbox) = open(&contents);
            for position in 0..mailbox.len() {
                let message = mailbox.message(position).expect("indexed message");
                exercise(&message);
                prop_assert!(message.parse() || message.subject().is_none());
            }
            prop_assert_eq!(mailbox.parse_batch(0..mailbox.len()).len(), mailbox.len());
        }
    }
}
