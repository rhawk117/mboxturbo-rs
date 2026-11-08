//! Field extraction over a parsed message, shared by `Message` and the column pipeline.

use std::borrow::Cow;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::LazyLock;

use mail_parser::{AddressList, DateTime, HeaderForm, HeaderName, MessageParser, MessagePart};

use crate::message::{Address, Attachment, Timestamp};

/// A parsed message borrowing its text from the mapping.
pub(crate) type Mail<'text> = mail_parser::Message<'text>;

/// The mbox separator that opens every stored message, ahead of the RFC 822 content.
const SEPARATOR: &[u8] = b"From ";

/// The shared parser: stock `mail-parser` behavior, except `Received:` stays raw so its text
/// reaches callers as written.
pub(crate) static FULL_PARSER: LazyLock<MessageParser> =
    LazyLock::new(|| builtin_table_with_raw_received(MessageParser::new()));

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
        .map(|header| unfold(String::from_utf8_lossy(header.raw_value())))
}

/// The `Date:` header as an instant plus the offset it was written in; `None` when the header
/// is absent or not a valid date.
///
/// A numeric zone in the raw header wins over the parser's own, which cannot hold offsets past
/// twelve hours.
pub(crate) fn date(mail: &Mail<'_>) -> Option<Timestamp> {
    let date = mail.date().filter(DateTime::is_valid)?;
    let offset_minutes = header_values(mail, "date")
        .last()
        .and_then(|raw| raw.split_whitespace().rev().find_map(numeric_zone_minutes))
        .unwrap_or_else(|| parsed_zone_minutes(&date));
    #[expect(
        clippy::disallowed_methods,
        reason = "offset_minutes is at most 23 * 60 + 59 in magnitude: numeric_zone_minutes \
                  keeps hours below 24 and minutes below 60, and parsed_zone_minutes reads a \
                  DateTime that is_valid bounds the same way, so * 60 fits in i64"
    )]
    let offset_seconds = i64::from(offset_minutes).strict_mul(60);
    #[expect(
        clippy::disallowed_methods,
        reason = "is_valid() keeps the year within 1900..=3000, so the local timestamp stays \
                  near 3.3e10 seconds and subtracting an offset under 86_400 cannot overflow i64"
    )]
    let unix_seconds = date.to_timestamp_local().strict_sub(offset_seconds);
    Some(Timestamp {
        unix_seconds,
        offset_minutes,
    })
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

/// The zone `date` carries, in minutes east of UTC.
///
/// `date` must satisfy `DateTime::is_valid`, which bounds the hours below 24 and the minutes
/// below 60.
fn parsed_zone_minutes(date: &DateTime) -> i32 {
    #[expect(
        clippy::disallowed_methods,
        reason = "the caller passes a DateTime that is_valid accepted, so tz_hour <= 23 and \
                  tz_minute <= 59: the sum is at most 1439 and negating it cannot overflow"
    )]
    let minutes = i32::from(date.tz_hour)
        .strict_mul(60)
        .strict_add(i32::from(date.tz_minute));
    if date.tz_before_gmt {
        #[expect(
            clippy::disallowed_methods,
            reason = "minutes is at most 1439, so negating it cannot overflow i32"
        )]
        let negated = minutes.strict_neg();
        negated
    } else {
        minutes
    }
}

/// A two-digit decimal number from `text`, or `None` when `text` is not one.
#[expect(
    clippy::disallowed_methods,
    reason = "the only caller passes two bytes already checked as ASCII digits, so parse cannot \
              fail and ok() only converts Result to Option; anything else is simply not a number"
)]
fn two_digit_number(text: &str) -> Option<i32> {
    text.parse::<i32>().ok()
}

/// A numeric zone such as `+0530` or `-0800` as minutes east of UTC; `None` for any other
/// token, including hours of 24 or more and minutes of 60 or more.
fn numeric_zone_minutes(token: &str) -> Option<i32> {
    let (direction, digits) = token
        .strip_prefix('+')
        .map(|unsigned| (1_i32, unsigned))
        .or_else(|| token.strip_prefix('-').map(|unsigned| (-1_i32, unsigned)))?;
    if digits.len() != 4 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let (hours_text, minutes_text) = digits.split_at_checked(2)?;
    let hours = two_digit_number(hours_text).filter(|&value| value < 24_i32)?;
    let minutes = two_digit_number(minutes_text).filter(|&value| value < 60_i32)?;
    #[expect(
        clippy::disallowed_methods,
        reason = "hours < 24 and minutes < 60 were just checked, so the magnitude is at most \
                  1439 and the sign multiply cannot overflow i32"
    )]
    let signed_minutes = hours
        .strict_mul(60)
        .strict_add(minutes)
        .strict_mul(direction);
    Some(signed_minutes)
}

/// `text` as one line: line breaks removed, surrounding whitespace trimmed. Borrows when the
/// text needs no joining.
pub(crate) fn unfold(text: Cow<'_, str>) -> Cow<'_, str> {
    if text.contains(['\r', '\n']) {
        return Cow::Owned(text.lines().collect::<String>().trim().to_owned());
    }
    match text {
        Cow::Borrowed(borrowed) => Cow::Borrowed(borrowed.trim()),
        Cow::Owned(owned) => Cow::Owned(owned.trim().to_owned()),
    }
}
