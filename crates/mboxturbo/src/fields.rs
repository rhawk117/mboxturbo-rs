//! Field extraction over a parsed message, shared by `Message` and the column pipeline.

use std::borrow::Cow;
use std::iter;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::LazyLock;

use mail_parser::{AddressList, HeaderForm, HeaderName, MessageParser, MessagePart};
use mboxturbo_headers::parse_date;

use crate::message::{Address, Attachment, Timestamp};

/// The shared parser: stock `mail-parser` behavior, except `Received:` stays raw so its text
/// reaches callers as written.
pub(crate) static FULL_PARSER: LazyLock<MessageParser> =
    LazyLock::new(|| builtin_table_with_raw_received(MessageParser::new()));

/// The mbox separator that opens every stored message, ahead of the RFC 822 content.
const SEPARATOR: &[u8] = b"From ";

/// Name of the header `date` reads, compared without regard to letter case.
const DATE_NAME: &[u8; 5] = b"date:";

/// A parsed message borrowing its text from the mapping.
pub(crate) type Mail<'text> = mail_parser::Message<'text>;

/// A header and the bytes that follow it.
type Split<'bytes> = (&'bytes [u8], &'bytes [u8]);

/// `parser` with `Received:` headers kept as raw text instead of parsed into a structure.
pub(crate) fn builtin_table_with_raw_received(parser: MessageParser) -> MessageParser {
    parser.header(HeaderName::Received, HeaderForm::Raw)
}

/// Runs `parse` and returns its message; `None` when it found no message or panicked.
///
/// A panic inside the parser is contained here, so one hostile message cannot take down the
/// process that is reading the mailbox.
#[expect(
    clippy::disallowed_methods,
    reason = "mail-parser can panic on adversarial input; the documented contract (README) is \
              that input making the parser panic reads as empty fields, so a contained panic \
              maps to None"
)]
pub(crate) fn contain_parser_panic<'text>(
    parse: impl FnOnce() -> Option<Mail<'text>>,
) -> Option<Mail<'text>> {
    catch_unwind(AssertUnwindSafe(parse)).ok().flatten()
}

/// `bytes` without its leading `From ` separator line, or unchanged when it has none.
///
/// A separator line with no newline after it has no RFC 822 content, so the result is empty.
pub(crate) fn strip_separator(bytes: &[u8]) -> &[u8] {
    if !bytes.starts_with(SEPARATOR) {
        return bytes;
    }
    let Some(from_newline) = memchr::memchr(b'\n', bytes).and_then(|newline| bytes.get(newline..))
    else {
        return &[];
    };
    from_newline.get(1..).unwrap_or(&[])
}

/// Every mailbox in `field`, groups flattened; empty when the header is absent.
pub(crate) fn addresses(field: Option<AddressList<'_>>) -> impl Iterator<Item = Address<'_>> {
    field
        .into_iter()
        .flat_map(|list| list.mailboxes())
        .map(|mailbox| Address {
            name: mailbox.name(),
            email: mailbox.address(),
        })
}

/// Every value of the header called `name` (any case) in file order, unfolded onto one line.
pub(crate) fn header_values<'mail, Name>(
    mail: &'mail Mail<'mail>,
    name: Name,
) -> impl Iterator<Item = Cow<'mail, str>>
where
    Name: AsRef<str>,
{
    mail.headers()
        .iter()
        .filter(move |header| header.name().as_str().eq_ignore_ascii_case(name.as_ref()))
        .map(|header| {
            unfold(String::from_utf8_lossy(strip_line_break(
                header.raw_value(),
            )))
        })
}

/// `raw` without its one final line break, which mail-parser keeps on a header's raw value.
pub(crate) fn strip_line_break(raw: &[u8]) -> &[u8] {
    raw.strip_suffix(b"\r\n")
        .or_else(|| raw.strip_suffix(b"\n"))
        .unwrap_or(raw)
}

/// The `Date:` header of `message` as an instant plus the offset it was written in; `None` when
/// the header is absent or [`mboxturbo_headers::parse_date`] rejects it.
///
/// `message` is the stored bytes, with or without its leading `From ` line. Only the head is
/// read, up to the first blank line, so a `Date:` line in the body never counts. When the
/// header repeats, the last occurrence wins; if that one does not parse, the result is `None`
/// even when an earlier one would. The index, the date columns and `Message::date` all read the
/// date here, so they cannot disagree.
pub(crate) fn date(message: &[u8]) -> Option<Timestamp> {
    let mut rest = message;
    let mut last = None;
    while let Some((header, remainder)) = next_header(rest) {
        if let Some(value) = date_value(header) {
            last = Some(value);
        }
        rest = remainder;
    }
    let value = last?;
    // Header issues are dropped here; surfacing them is the job of the header-issue columns.
    let (instant, _issues) = parse_date(value.as_bytes()).into_parts();
    instant.map(|found| Timestamp {
        offset_minutes: i32::from(found.offset_minutes()),
        unix_seconds: found.unix_seconds(),
    })
}

/// The text after the colon of `header` when it is a `Date:` header, unfolded onto one line.
fn date_value(header: &[u8]) -> Option<Cow<'_, str>> {
    let (name, value) = header.split_at_checked(DATE_NAME.len())?;
    name.eq_ignore_ascii_case(DATE_NAME)
        .then(|| unfold(String::from_utf8_lossy(value)))
}

/// The name and the raw value of every header in the head of `message`, in file order.
///
/// `message` is the stored bytes, with or without its leading `From ` line. The walk stops at
/// the first blank line, so a header-looking line in the body never shows up. The name is the
/// text before the first colon, as written; the value is everything after that colon, folds
/// included, without the final line break. A line with no colon is skipped.
pub(crate) fn raw_headers(message: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> {
    let mut rest = strip_separator(message);
    iter::from_fn(move || {
        loop {
            let (header, remainder) = next_header(rest)?;
            rest = remainder;
            if let Some(split) = split_header(header) {
                return Some(split);
            }
        }
    })
}

/// The name and the value of `header` around its first colon; `None` when it has no colon.
fn split_header(header: &[u8]) -> Option<Split<'_>> {
    let (name, from_colon) = header.split_at_checked(memchr::memchr(b':', header)?)?;
    let value = from_colon.get(1..)?;
    Some((name, value.strip_suffix(b"\r").unwrap_or(value)))
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

/// Every plain-text body; an HTML-only message yields its HTML converted to text.
pub(crate) fn text_bodies<'mail>(
    mail: &'mail Mail<'mail>,
) -> impl Iterator<Item = Cow<'mail, str>> {
    (0..mail.text_body().len()).filter_map(move |position| mail.body_text(position))
}

/// Every HTML body; a text-only message yields its text converted to HTML.
pub(crate) fn html_bodies<'mail>(
    mail: &'mail Mail<'mail>,
) -> impl Iterator<Item = Cow<'mail, str>> {
    (0..mail.html_body().len()).filter_map(move |position| mail.body_html(position))
}

/// Every attachment of `mail`, with its transfer encoding removed.
pub(crate) fn attachments<'mail>(
    mail: &'mail Mail<'mail>,
) -> impl Iterator<Item = Attachment<'mail>> {
    mail.attachments().map(|part| {
        let content_type = part.content_type();
        Attachment {
            filename: part.attachment_name(),
            media_type: content_type.as_ref().map(mail_parser::ContentType::ctype),
            media_subtype: content_type
                .as_ref()
                .and_then(mail_parser::ContentType::subtype),
            data: attachment_bytes(part),
        }
    })
}

/// The decoded bytes of `part`; an attached message yields its raw bytes undecoded.
fn attachment_bytes(part: MessagePart<'_>) -> Cow<'_, [u8]> {
    part.nested()
        .map_or_else(|| part.decoded(), |nested| Cow::Borrowed(nested.raw()))
}

/// `text` as one line: line breaks removed, surrounding whitespace trimmed. Borrows when the
/// text needs no joining and is already borrowed; allocates at most once otherwise.
pub(crate) fn unfold(text: Cow<'_, str>) -> Cow<'_, str> {
    if text.contains(['\r', '\n']) {
        let mut joined = text.lines().collect::<String>();
        trim_in_place(&mut joined);
        return Cow::Owned(joined);
    }
    match text {
        Cow::Borrowed(borrowed) => Cow::Borrowed(borrowed.trim()),
        Cow::Owned(mut owned) => {
            trim_in_place(&mut owned);
            Cow::Owned(owned)
        },
    }
}

/// Removes the leading and trailing whitespace of `text` without reallocating.
fn trim_in_place(text: &mut String) {
    text.truncate(text.trim_end().len());
    let leading = text.len().saturating_sub(text.trim_start().len());
    drop(text.drain(..leading));
}
