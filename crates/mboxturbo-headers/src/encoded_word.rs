//! Lossy decoding of RFC 2047 encoded words.
//!
//! Words are located in one forward pass whose every scan stops at the next `?` or
//! whitespace byte, so the work stays linear in the input length however hostile the input.

use std::borrow::Cow;
use std::{iter, mem};

use encoding_rs::{Encoding, REPLACEMENT};

use crate::caps::{Cap, MAX_ENCODED_WORDS};
use crate::issue::{Issue, IssueKind, Parsed};
use crate::tokenize::{bound, slice_checked};

/// The output being built.
struct Decoder {
    /// Whether the last thing emitted was a successfully decoded word.
    after_word: bool,
    /// Issues found so far.
    issues: Vec<Issue>,
    /// The decoded text so far.
    out: String,
}

/// The result of locating every word in a value.
#[derive(Debug)]
struct Found<'src> {
    /// Offset of the first word beyond [`MAX_ENCODED_WORDS`]; the scan stopped there.
    cap_offset: Option<usize>,
    /// Issues from locating the words.
    issues: Vec<Issue>,
    /// The bytes after the last word found.
    tail: &'src [u8],
    /// Offset where `tail` starts.
    tail_offset: usize,
    /// The words, in order.
    words: Vec<Word<'src>>,
}

/// One syntactically valid `=?charset?encoding?text?=` span of the input, with the bytes
/// between the previous word (or the input start) and it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Word<'src> {
    /// The charset field, possibly with an RFC 2231 `*language` suffix.
    charset: &'src [u8],
    /// The single encoding byte: `B` or `Q` in either case, or anything else (invalid).
    encoding: u8,
    /// The bytes before the opening `=?` that follow the previous word.
    gap: &'src [u8],
    /// The whole word, `=?` to `?=` inclusive.
    raw: &'src [u8],
    /// Offset of the opening `=?`.
    start: usize,
    /// The encoded text field.
    text: &'src [u8],
}

impl Decoder {
    /// Copies `bytes`, found at `offset`, as text, reporting invalid UTF-8 at its first bad byte.
    fn text(&mut self, bytes: &[u8], offset: usize) {
        match str::from_utf8(bytes) {
            Ok(text) => self.out.push_str(text),
            Err(error) => {
                let bad = offset.saturating_add(error.valid_up_to());
                self.issues.push(Issue::new(IssueKind::InvalidUtf8, bad));
                self.out.push_str(&String::from_utf8_lossy(bytes));
            },
        }
    }

    /// Handles one word: drops the whitespace separating it from a decoded word before it,
    /// and decodes it or falls back to its raw text.
    fn word(&mut self, word: &Word<'_>) {
        let gap_offset = word.start.saturating_sub(word.gap.len());
        if !(self.after_word && word.gap.iter().all(|byte| is_space(*byte))) {
            self.text(word.gap, gap_offset);
        }
        let mut decoded = String::new();
        self.after_word = match decode_word(word, &mut decoded) {
            Ok(malformed) => {
                if malformed {
                    self.issues
                        .push(Issue::new(IssueKind::MalformedBytes, word.start));
                }
                self.out.push_str(&decoded);
                true
            },
            Err(kind) => {
                self.issues.push(Issue::new(kind, word.start));
                self.text(word.raw, word.start);
                false
            },
        };
    }
}

/// Decodes base64 text, tolerating missing padding; `None` for a byte outside the alphabet
/// or a dangling single digit.
fn decode_base64(text: &[u8]) -> Option<Vec<u8>> {
    let digits_end = text
        .iter()
        .rposition(|byte| *byte != b'=')
        .map_or(0, |last| last.saturating_add(1));
    let mut decoded = Vec::with_capacity(digits_end);
    for chunk in text.get(..digits_end)?.chunks(4) {
        if chunk.len() == 1 {
            return None;
        }
        let padded = chunk.iter().copied().chain(iter::repeat(b'A')).take(4);
        let mut padded_digits = padded;
        let bits = padded_digits.try_fold(0_u32, |acc, byte| {
            Some((acc << 6_u32) | u32::from(sextet(byte)?))
        })?;
        let little_endian = bits.to_le_bytes();
        let kept = chunk.len().saturating_sub(1);
        decoded.extend(little_endian.get(..3)?.iter().rev().take(kept));
    }
    Some(decoded)
}

/// Decodes the RFC 2047 encoded words in `value`, which is header text.
///
/// Charset names are case-insensitive and an RFC 2231 `*language` suffix is ignored.
/// Whitespace between two adjacent decoded words is dropped (RFC 2047 section 6.2); all
/// other text is kept, with invalid UTF-8 outside words replaced by U+FFFD and reported as
/// [`IssueKind::InvalidUtf8`].
///
/// A word that cannot be decoded stays in the output as its raw text with an issue at its
/// `=?` offset: [`IssueKind::UnknownCharset`], [`IssueKind::InvalidEncoding`] (bad
/// encoding letter, base64 or Q text), or [`IssueKind::MalformedBytes`] when the bytes were
/// not valid in the charset and became U+FFFD. Words beyond [`MAX_ENCODED_WORDS`] stay raw
/// and are reported once as [`IssueKind::CapExceeded`] at the first such word.
///
/// Input past [`crate::caps::MAX_HEADER_BYTES`] is dropped and reported once as
/// [`IssueKind::CapExceeded`].
///
/// The result borrows `value` when it is valid UTF-8 and holds no encoded word.
#[must_use]
pub fn decode_encoded_words(value: &[u8]) -> Parsed<Cow<'_, str>> {
    let (head, cut) = bound(value);
    let mut found = find_words(head);
    if found.words.is_empty()
        && found.cap_offset.is_none()
        && found.issues.is_empty()
        && let Ok(text) = str::from_utf8(head)
    {
        return Parsed::new(Cow::Borrowed(text), cut);
    }
    let mut decoder = Decoder {
        after_word: false,
        issues: mem::take(&mut found.issues),
        out: String::new(),
    };
    for word in &found.words {
        decoder.word(word);
    }
    decoder.text(found.tail, found.tail_offset);
    if let Some(offset) = found.cap_offset {
        let kind = IssueKind::CapExceeded {
            cap: Cap::EncodedWords,
        };
        decoder.issues.push(Issue::new(kind, offset));
    }
    decoder.issues.extend(cut);
    Parsed::new(Cow::Owned(decoder.out), decoder.issues)
}

/// Decodes Q text (`_` is a space, `=XX` a byte); `None` for a bad or truncated `=XX`.
fn decode_q(text: &[u8]) -> Option<Vec<u8>> {
    let mut decoded = Vec::with_capacity(text.len());
    let mut bytes = text.iter().copied();
    while let Some(byte) = bytes.next() {
        decoded.push(match byte {
            b'_' => b' ',
            b'=' => {
                let high = hex_digit(bytes.next()?)?;
                (high << 4_u8) | hex_digit(bytes.next()?)?
            },
            other => other,
        });
    }
    Some(decoded)
}

/// Decodes the word into `out`, returning whether malformed bytes became U+FFFD. On error
/// `out` is untouched.
fn decode_word(word: &Word<'_>, out: &mut String) -> Result<bool, IssueKind> {
    let encoding = lookup_charset(word.charset).ok_or(IssueKind::UnknownCharset)?;
    let bytes = match word.encoding {
        b'B' | b'b' => decode_base64(word.text),
        b'Q' | b'q' => decode_q(word.text),
        _ => None,
    }
    .ok_or(IssueKind::InvalidEncoding)?;
    let (decoded, malformed) = encoding.decode_without_bom_handling(&bytes);
    out.push_str(&decoded);
    Ok(malformed)
}

/// Length of the field at the start of `bytes`: the bytes before the first `?`. A
/// whitespace byte or the end of input before that `?` means there is no field.
fn field_len(bytes: &[u8]) -> Option<usize> {
    let len = bytes
        .iter()
        .position(|byte| *byte == b'?' || is_space(*byte))?;
    (bytes.get(len) == Some(&b'?')).then_some(len)
}

/// Finds the words to decode, stopping at the first one beyond [`MAX_ENCODED_WORDS`].
fn find_words(value: &[u8]) -> Found<'_> {
    let mut words: Vec<Word<'_>> = Vec::new();
    let mut prev_end = 0;
    let mut pos = 0;
    let mut cap_offset = None;
    let mut issues = Vec::new();
    while let Some(start) = next_marker(value, pos) {
        let Some(word) = locate_word(value, start, prev_end) else {
            pos = start.saturating_add(1);
            continue;
        };
        if words.len() >= MAX_ENCODED_WORDS {
            cap_offset = Some(start);
            break;
        }
        prev_end = start.saturating_add(word.raw.len());
        pos = prev_end;
        words.push(word);
    }
    let tail = slice_checked(value, 0, prev_end..value.len(), &mut issues);
    Found {
        cap_offset,
        issues,
        tail,
        tail_offset: prev_end,
        words,
    }
}

/// The value of one hexadecimal digit.
const fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte.wrapping_sub(b'0')),
        b'A'..=b'F' => Some(byte.wrapping_sub(b'A').wrapping_add(10)),
        b'a'..=b'f' => Some(byte.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    }
}

/// Whether `byte` is linear whitespace, which never occurs inside an encoded word.
const fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

/// Parses the word whose `=?` starts at `start`, if the bytes there form one. `prev_end`
/// is where the previous word ended.
fn locate_word(value: &[u8], start: usize, prev_end: usize) -> Option<Word<'_>> {
    let charset_start = start.saturating_add(2);
    let charset_len = field_len(value.get(charset_start..)?).filter(|len| *len > 0)?;
    let encoding_pos = charset_start.saturating_add(charset_len).saturating_add(1);
    let encoding = *value.get(encoding_pos)?;
    let text_start = encoding_pos.saturating_add(2);
    if value.get(encoding_pos.saturating_add(1)) != Some(&b'?') {
        return None;
    }
    let text_end = text_start.saturating_add(field_len(value.get(text_start..)?)?);
    if value.get(text_end.saturating_add(1)) != Some(&b'=') {
        return None;
    }
    Some(Word {
        charset: value.get(charset_start..charset_start.saturating_add(charset_len))?,
        encoding,
        gap: value.get(prev_end..start)?,
        raw: value.get(start..text_end.saturating_add(2))?,
        start,
        text: value.get(text_start..text_end)?,
    })
}

/// The encoding named by the charset field, ignoring an RFC 2231 `*language` suffix.
fn lookup_charset(label: &[u8]) -> Option<&'static Encoding> {
    let name = label.split(|byte| *byte == b'*').next()?;
    Encoding::for_label(name).filter(|encoding| *encoding != REPLACEMENT)
}

/// Offset of the first `=?` at or after `from`.
fn next_marker(value: &[u8], from: usize) -> Option<usize> {
    let rest = value.get(from..)?;
    let rel = rest.windows(2).position(|pair| pair == b"=?")?;
    Some(from.saturating_add(rel))
}

/// The value of one base64 digit.
const fn sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte.wrapping_sub(b'A')),
        b'a'..=b'z' => Some(byte.wrapping_sub(b'a').wrapping_add(26)),
        b'0'..=b'9' => Some(byte.wrapping_sub(b'0').wrapping_add(52)),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::decode_encoded_words;
    use crate::caps::{Cap, MAX_ENCODED_WORDS, MAX_HEADER_BYTES};
    use crate::issue::IssueKind;

    /// An issue as `(kind, offset)`.
    type Found = (IssueKind, usize);

    /// Decodes `input` and returns the text with each issue as `(kind, offset)`.
    fn decode(input: &str) -> (String, Vec<Found>) {
        let (text, issues) = decode_encoded_words(input.as_bytes()).into_parts();
        let found = issues
            .iter()
            .map(|issue| (issue.kind(), issue.offset()))
            .collect();
        (text.into_owned(), found)
    }

    #[test]
    fn a_q_word_in_utf8_decodes_to_text() {
        let (text, issues) = decode("=?utf-8?q?caf=C3=A9_au_lait?=");
        assert_eq!(
            text, "caf\u{e9} au lait",
            "q text decodes with _ as a space"
        );
        assert!(
            issues.is_empty(),
            "a valid word reports nothing: {issues:?}"
        );
    }

    #[test]
    fn a_b_word_in_latin1_decodes_with_a_case_insensitive_charset_name() {
        let (text, issues) = decode("=?ISO-8859-1?B?Y2Fm6Q==?=");
        assert_eq!(text, "caf\u{e9}", "the latin-1 byte 0xE9 becomes e-acute");
        assert!(
            issues.is_empty(),
            "a valid word reports nothing: {issues:?}"
        );
    }

    #[test]
    fn base64_without_padding_still_decodes() {
        let (text, issues) = decode("=?utf-8?b?Y2Fmw6k?=");
        assert_eq!(text, "caf\u{e9}", "missing = padding is tolerated");
        assert!(
            issues.is_empty(),
            "tolerated padding is no issue: {issues:?}"
        );
    }

    #[test]
    fn a_language_suffix_on_the_charset_is_ignored() {
        let (text, issues) = decode("=?utf-8*en?q?hello?=");
        assert_eq!(text, "hello", "RFC 2231 language is dropped from the label");
        assert!(issues.is_empty(), "the suffix is no issue: {issues:?}");
    }

    #[test]
    fn whitespace_between_adjacent_words_is_dropped_but_other_text_is_kept() {
        let (text, _) = decode("a =?utf-8?q?b?= \r\n =?utf-8?q?c?= d =?utf-8?q?e?=");
        assert_eq!(
            text, "a bc d e",
            "RFC 2047 6.2 drops only the gap between words"
        );
    }

    #[test]
    fn an_unknown_charset_keeps_the_raw_word_and_reports_its_offset() {
        let (text, issues) = decode("x =?bogus?q?hi?=");
        assert_eq!(text, "x =?bogus?q?hi?=", "the raw word stays in the text");
        assert_eq!(
            issues,
            vec![(IssueKind::UnknownCharset, 2)],
            "issue at the =? offset"
        );
    }

    #[test]
    fn invalid_base64_keeps_the_raw_word_and_reports_it() {
        let (text, issues) = decode("=?utf-8?b?a$b?=");
        assert_eq!(text, "=?utf-8?b?a$b?=", "the raw word stays in the text");
        assert_eq!(
            issues,
            vec![(IssueKind::InvalidEncoding, 0)],
            "a $ is not base64"
        );
    }

    #[test]
    fn a_truncated_q_escape_keeps_the_raw_word_and_reports_it() {
        let (text, issues) = decode("=?utf-8?q?ab=4?=");
        assert_eq!(text, "=?utf-8?q?ab=4?=", "the raw word stays in the text");
        assert_eq!(
            issues,
            vec![(IssueKind::InvalidEncoding, 0)],
            "=4 lacks a digit"
        );
    }

    #[test]
    fn an_unknown_encoding_letter_is_an_invalid_encoding() {
        let (_, issues) = decode("=?utf-8?x?abc?=");
        assert_eq!(
            issues,
            vec![(IssueKind::InvalidEncoding, 0)],
            "only B and Q exist"
        );
    }

    #[test]
    fn bytes_invalid_in_the_charset_become_the_replacement_character() {
        let (text, issues) = decode("=?utf-8?q?a=FFb?=");
        assert_eq!(text, "a\u{fffd}b", "the malformed byte is replaced");
        assert_eq!(
            issues,
            vec![(IssueKind::MalformedBytes, 0)],
            "reported at the word"
        );
    }

    #[test]
    fn text_without_a_word_borrows_the_input() {
        let parsed = decode_encoded_words(b"plain =? text ?=");
        assert!(
            matches!(parsed.value(), Cow::Borrowed("plain =? text ?=")),
            "valid UTF-8 with no word is not copied",
        );
        assert!(parsed.issues().is_empty(), "nothing to report");
    }

    #[test]
    fn invalid_utf8_outside_a_word_is_replaced_and_reported() {
        let (text, issues) = decode_encoded_words(b"ab\xFFcd =?utf-8?q?e?=").into_parts();
        assert_eq!(text, "ab\u{fffd}cd e", "the stray byte is replaced");
        assert_eq!(
            issues
                .iter()
                .map(|issue| (issue.kind(), issue.offset()))
                .collect::<Vec<_>>(),
            vec![(IssueKind::InvalidUtf8, 2)],
            "reported at the bad byte",
        );
    }

    #[test]
    fn a_value_one_byte_over_the_header_cap_is_cut_and_reported_at_the_cap() {
        let word = "=?utf-8?q?b?=";
        let input = format!("{word}{}", "a".repeat(MAX_HEADER_BYTES - word.len() + 1));
        let (text, issues) = decode(&input);
        assert_eq!(
            text,
            format!("b{}", "a".repeat(MAX_HEADER_BYTES - word.len())),
            "the word before the cut is decoded and the text after it is dropped"
        );
        assert_eq!(
            issues,
            vec![(
                IssueKind::CapExceeded {
                    cap: Cap::HeaderBytes
                },
                MAX_HEADER_BYTES
            )],
            "one issue at the cap"
        );
    }

    #[test]
    fn words_beyond_the_cap_stay_raw_and_are_reported_once() {
        let input = vec!["=?utf-8?q?a?="; MAX_ENCODED_WORDS + 2].join(" ");
        let (text, issues) = decode(&input);
        let expected = format!(
            "{}{}",
            "a".repeat(MAX_ENCODED_WORDS),
            " =?utf-8?q?a?=".repeat(2)
        );
        assert_eq!(
            text, expected,
            "only the first MAX_ENCODED_WORDS words decode"
        );
        assert_eq!(
            issues,
            vec![(
                IssueKind::CapExceeded {
                    cap: Cap::EncodedWords
                },
                MAX_ENCODED_WORDS * 14
            )],
            "one issue at the first excess word",
        );
    }

    #[test]
    fn a_long_run_of_unfinished_markers_is_handled_without_panic() {
        let input = "=?a".repeat(200_000);
        let (text, issues) = decode(&input);
        assert_eq!(text, input, "unfinished words are plain text");
        assert!(issues.is_empty(), "plain text is no issue: {issues:?}");
    }
}
