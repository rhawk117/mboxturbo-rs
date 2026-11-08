//! Hostile and malformed messages: every accessor must answer without panicking.

#[cfg(test)]
mod hostile {
    use std::fs;
    use std::hint::black_box;

    use mboxturbo::{Mailbox, Message};
    use proptest::collection;
    use proptest::prelude::*;
    use tempfile::TempDir;

    fn open(contents: &[u8]) -> (TempDir, Mailbox) {
        let directory =
            tempfile::tempdir().expect("a temporary directory can be created for the fixture mbox");
        let path = directory.path().join("hostile.mbox");
        fs::write(&path, contents).expect("the hostile bytes are written to the fixture mbox");
        let mailbox = Mailbox::open(&path)
            .expect("the hostile mbox opens, since malformed messages are not an open error");
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
        for attachment in message.attachments() {
            let _attachment =
                black_box((attachment.data.len(), attachment.content_type().is_some()));
        }
        let _raw = black_box(message.raw());
    }

    fn only_message(contents: &[u8]) -> (TempDir, Message) {
        let (directory, mailbox) = open(contents);
        let message = mailbox
            .message(0)
            .expect("the fixture mbox holds a message at position 0");
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
    fn a_nested_message_without_headers_is_one_attachment_holding_its_body() {
        let (_directory, message) =
            only_message(b"From a\nContent-Type: message/rfc822\n\nno headers here\n");
        exercise(&message);
        let attachments: Vec<Vec<u8>> = message
            .attachments()
            .map(|attachment| attachment.data.to_vec())
            .collect();
        assert_eq!(
            attachments,
            [b"no headers here
"
            .to_vec()],
            "the header-less nested message is one attachment holding its body bytes"
        );
    }

    #[test]
    fn zones_past_twelve_hours_keep_their_offset_and_instant() {
        let (_directory, message) = only_message(
            b"From a\nDate: Mon, 01 Jan 2024 12:00:00 +1300 (NZDT)\nSubject: s\n\nbody\n",
        );
        assert_eq!(
            message
                .date()
                .map(|stamp| (stamp.unix_seconds, stamp.offset_minutes)),
            Some((1_704_063_600_i64, 780_i32)),
            "12:00 at +1300 is 23:00 UTC the day before"
        );
    }

    #[test]
    fn header_names_with_dots_are_found() {
        let (_directory, message) = only_message(b"From a\nX.Trace: route\nSubject: s\n\nbody\n");
        assert_eq!(
            message.header("x.trace").as_deref(),
            Some("route"),
            "a header name containing a dot is matched case-insensitively"
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
            collection::vec(any::<u8>(), 0..12),
        ];
        collection::vec(fragment, 0..32).prop_map(|parts| parts.concat())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn every_accessor_answers_on_any_input(contents in hostile_fragments()) {
            let (_directory, mailbox) = open(&contents);
            for position in 0..mailbox.len() {
                let message = mailbox.message(position).expect("a position below len() is indexed");
                exercise(&message);
                let before = message.subject().map(str::to_owned);
                let parsed = message.parse();
                prop_assert_eq!(
                    message.subject(),
                    before.as_deref(),
                    "a full parse leaves the subject unchanged (parse() is true if a MIME part was \
                     found, false if none was found or a parser panic was contained: {})",
                    parsed
                );
            }
        }

        #[test]
        fn a_whole_mailbox_batch_reports_exactly_the_unparsed_positions(
            contents in hostile_fragments()
        ) {
            let (_directory, mailbox) = open(&contents);
            let batch = mailbox.parse_batch(0..mailbox.len());
            prop_assert_eq!(
                batch.messages.len(),
                mailbox.len(),
                "a batch over the whole mailbox keeps every message"
            );
            let failed: Vec<usize> = (0..mailbox.len())
                .filter(|&position| {
                    !mailbox.message(position)
                        .expect("position below len() is indexed")
                        .parse()
                })
                .collect();
            prop_assert_eq!(
                batch.unparsed,
                failed,
                "unparsed lists exactly the positions whose parse is false"
            );
        }
    }
}
