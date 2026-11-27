//! Header-only `Date:` extraction: the unix seconds `Message::date` reports, without parsing
//! the whole message.

use crate::fields;

/// The unix seconds `Message::date` reports for `message`, or `None` when it has no usable date.
///
/// `message` is the stored bytes, with or without its leading `From ` line. The header is picked
/// and parsed by [`fields::date`], the same function behind the date columns and `Message::date`.
/// Absent, unparsable and out-of-range dates all give `None`, so a real date at exactly the Unix
/// epoch is `Some(0)`.
pub(crate) fn extract(message: &[u8]) -> Option<i64> {
    fields::date(message).map(|stamp| stamp.unix_seconds)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::iter::repeat_n;

    use tempfile::NamedTempFile;

    use super::extract;
    use crate::Mailbox;

    const FOLDED: &[u8] = b"From a\nDate: Mon, 01 Jan 2024\n 12:00:00 +0000\nSubject: s\n\nb\n";
    const LOWER: &[u8] = b"From a\ndAtE: Mon, 01 Jan 2024 12:00:00 -0500\n\nb\n";
    const NZ: &[u8] = b"From a\nDate: Mon, 01 Jan 2024 12:00:00 +1300 (NZDT)\n\nb\n";
    const KIRITIMATI: &[u8] = b"From a\nDate: Mon, 01 Jan 2024 12:00:00 +1400\n\nb\n";
    const TWICE: &[u8] = b"From a\nDate: Mon, 01 Jan 2024 12:00:00 +0000\n\
                           Date: Tue, 02 Jan 2024 12:00:00 +0000\n\nb\n";
    const CRLF: &[u8] = b"From a\r\nDate: Mon, 01 Jan 2024 12:00:00 +0100\r\n\r\nb\r\n";
    const ASCTIME: &[u8] = b"From a\nDate: Mon Jan  1 12:00:00 2024\n\nb\n";
    const BAD: &[u8] = b"From a\nDate: not a date\n\nb\n";
    const BODY_ONLY: &[u8] = b"From a\nSubject: s\n\nDate: Mon, 01 Jan 2024 12:00:00 +0000\n";
    const NONE: &[u8] = b"From a\nSubject: s\n\nb\n";

    fn mailbox(messages: &[&[u8]]) -> (NamedTempFile, Mailbox) {
        let mut file = NamedTempFile::new().expect("temp file is created");
        for message in messages {
            file.write_all(message).expect("fixture is written");
        }
        let mailbox = Mailbox::open(file.path()).expect("fixture mbox opens");
        (file, mailbox)
    }

    fn assert_agrees(message: &[u8]) {
        let (_file, mailbox) = mailbox(&[message]);
        let expected = mailbox
            .message(0)
            .expect("the fixture holds one message")
            .date()
            .map(|stamp| stamp.unix_seconds);
        let raw = mailbox.raw(0).expect("message 0 has raw bytes");
        assert_eq!(extract(raw), expected, "extractor matches Message::date");
    }

    #[test]
    fn every_zone_and_layout_matches_the_message_accessor() {
        for message in [FOLDED, LOWER, NZ, KIRITIMATI, TWICE, CRLF] {
            assert_agrees(message);
            assert!(
                extract(message).is_some(),
                "the fixture carries a real date"
            );
        }
    }

    #[test]
    fn an_asctime_date_is_dated_through_the_lenient_parser() {
        assert_eq!(
            extract(ASCTIME),
            Some(1_704_110_400),
            "asctime reads as 2024-01-01 12:00:00 UTC"
        );
        let (_file, mailbox) = mailbox(&[ASCTIME]);
        assert_eq!(
            mailbox.date(0),
            Some(1_704_110_400),
            "the index carries the asctime date"
        );
    }

    #[test]
    fn the_last_of_two_date_headers_wins() {
        assert_eq!(
            extract(TWICE),
            Some(1_704_196_800),
            "2 Jan 2024 12:00 UTC, not the first header"
        );
    }

    #[test]
    fn plus_1400_is_not_clamped_to_the_parsers_twelve_hours() {
        assert_eq!(
            extract(KIRITIMATI),
            Some(1_704_060_000),
            "12:00 at +1400 is 22:00 UTC the day before"
        );
    }

    #[test]
    fn missing_unparsable_and_body_only_dates_are_none() {
        for message in [BAD, BODY_ONLY, NONE] {
            assert_agrees(message);
            assert_eq!(extract(message), None, "no usable head date reads as none");
        }
    }

    #[test]
    fn a_crlf_blank_line_ends_the_head_so_a_body_date_is_ignored() {
        const CRLF_BODY_ONLY: &[u8] =
            b"From a\r\nSubject: s\r\n\r\nDate: Mon, 01 Jan 2024 12:00:00 +0000\r\n";
        assert_agrees(CRLF_BODY_ONLY);
        assert_eq!(
            extract(CRLF_BODY_ONLY),
            None,
            "a Date line after the CRLF blank line is body text"
        );
    }

    #[test]
    fn nothing_past_the_first_blank_line_is_read() {
        let mut message = b"From a\nSubject: s\n\n".to_vec();
        message.extend(repeat_n(b'x', 1 << 20));
        message.extend_from_slice(b"\nDate: Mon, 01 Jan 2024 12:00:00 +0000\n");
        assert_eq!(extract(&message), None, "a body Date line is ignored");
    }
}
