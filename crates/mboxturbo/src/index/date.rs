//! Header-only `Date:` extraction: the unix seconds `Message::date` reports, without parsing
//! the whole message.

use std::borrow::Cow;

use mail_parser::DateTime;

use crate::fields::{timestamp, unfold};

/// Name of the header read, compared without regard to letter case.
const NAME: &[u8; 5] = b"date:";

/// A header and the bytes that follow it.
type Split<'bytes> = (&'bytes [u8], &'bytes [u8]);

/// The unix seconds `Message::date` reports for `message`, or `None` when it has no usable date.
///
/// `message` is the stored bytes, with or without its leading `From ` line. Only the head is
/// read, up to the first blank line, so a `Date:` line in the body never counts. When the
/// header repeats, the last occurrence wins, as in `mail-parser`; if that one does not parse,
/// the result is `None` even when an earlier one would. Absent, unparsable and out-of-range
/// dates all give `None`, so a real date at exactly the Unix epoch is `Some(0)`.
pub(crate) fn extract(message: &[u8]) -> Option<i64> {
    let mut rest = message;
    let mut last = None;
    while let Some((header, remainder)) = next_header(rest) {
        if let Some(value) = date_value(header) {
            last = Some(value);
        }
        rest = remainder;
    }
    let value = last?;
    parse(&value)
}

/// The unix seconds of the unfolded header text `value`; `None` when it is not a valid date.
fn parse(value: &str) -> Option<i64> {
    let date = DateTime::parse_rfc822(value).filter(DateTime::is_valid)?;
    timestamp(&date, value).map(|stamp| stamp.unix_seconds)
}

/// The text after the colon of `header` when it is a `Date:` header, unfolded onto one line.
fn date_value(header: &[u8]) -> Option<Cow<'_, str>> {
    let (name, value) = header.split_at_checked(NAME.len())?;
    name.eq_ignore_ascii_case(NAME)
        .then(|| unfold(String::from_utf8_lossy(value)))
}

/// The offset of the first newline in `bytes`, or its length when there is none.
fn line_end(bytes: &[u8]) -> usize {
    memchr::memchr(b'\n', bytes).unwrap_or(bytes.len())
}

/// Whether `line` (without its newline) ends the head: empty, or a lone carriage return.
const fn is_blank(line: &[u8]) -> bool {
    matches!(line, [] | [b'\r'])
}

/// The offset where the header starting at the front of `rest` ends: the end of its first line,
/// pushed past every following line that starts with a space or a tab.
fn header_end(rest: &[u8]) -> usize {
    let mut end = line_end(rest);
    while let Some(after) = end.checked_add(1).and_then(|start| rest.get(start..)) {
        if !matches!(after.first(), Some(b' ' | b'\t')) {
            break;
        }
        end = end.saturating_add(1).saturating_add(line_end(after));
    }
    end
}

/// The next header at the front of `rest`, continuation lines included and the final newline
/// excluded, with what follows it; `None` at the first blank line or the end of the bytes.
fn next_header(rest: &[u8]) -> Option<Split<'_>> {
    if is_blank(rest.get(..line_end(rest))?) {
        return None;
    }
    let end = header_end(rest);
    let header = rest.get(..end)?;
    let remainder = end
        .checked_add(1)
        .and_then(|start| rest.get(start..))
        .unwrap_or(&[]);
    Some((header, remainder))
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
