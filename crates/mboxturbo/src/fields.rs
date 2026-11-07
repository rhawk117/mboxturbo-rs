//! Field extraction over a parsed message, shared by `Message` and the column pipeline.

use std::borrow::Cow;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::LazyLock;

use mail_parser::{HeaderName, MessageParser, MessagePart, MimeHeaders};

use crate::message::{Address, Attachment, Timestamp};

pub(crate) type Mail<'x> = mail_parser::Message<'x>;

const SEPARATOR: &[u8] = b"From ";

pub(crate) static FULL_PARSER: LazyLock<MessageParser> =
    LazyLock::new(|| builtin_table_with_raw_received(MessageParser::new()));

pub(crate) fn builtin_table_with_raw_received(parser: MessageParser) -> MessageParser {
    parser
        .with_mime_headers()
        .with_date_headers()
        .with_address_headers()
        .with_message_ids()
        .header_text(HeaderName::Subject)
        .header_text(HeaderName::Comments)
        .header_address(HeaderName::ListArchive)
        .header_address(HeaderName::ListHelp)
        .header_address(HeaderName::ListId)
        .header_address(HeaderName::ListOwner)
        .header_address(HeaderName::ListPost)
        .header_address(HeaderName::ListSubscribe)
        .header_address(HeaderName::ListUnsubscribe)
        .header_id(HeaderName::ReturnPath)
        .header_comma_separated(HeaderName::Keywords)
        .header_comma_separated(HeaderName::ContentLanguage)
        .header_raw(HeaderName::Received)
}

pub(crate) fn contain_parser_panic<'a>(
    parse: impl FnOnce() -> Option<Mail<'a>>,
) -> Option<Mail<'a>> {
    catch_unwind(AssertUnwindSafe(parse)).ok().flatten()
}

pub(crate) fn strip_separator(bytes: &[u8]) -> &[u8] {
    if !bytes.starts_with(SEPARATOR) {
        return bytes;
    }
    memchr::memchr(b'\n', bytes)
        .and_then(|newline| bytes.get(newline.strict_add(1)..))
        .unwrap_or_default()
}

pub(crate) fn addresses<'a>(
    field: Option<&'a mail_parser::Address<'a>>,
) -> impl Iterator<Item = Address<'a>> {
    field
        .into_iter()
        .flat_map(mail_parser::Address::iter)
        .map(|addr| Address {
            name: addr.name.as_deref(),
            email: addr.address.as_deref(),
        })
}

pub(crate) fn header_values<'a, N: AsRef<str>>(
    mail: &'a Mail<'a>,
    name: N,
) -> impl Iterator<Item = Cow<'a, str>> + use<'a, N> {
    let raw = mail.raw_message();
    mail.headers()
        .iter()
        .filter(move |header| header.name.as_str().eq_ignore_ascii_case(name.as_ref()))
        .filter_map(move |header| raw_header_value(raw, header))
}

pub(crate) fn date(mail: &Mail<'_>) -> Option<Timestamp> {
    let date = mail.date().filter(|date| date.is_valid())?;
    let offset_minutes = header_values(mail, "date")
        .last()
        .and_then(|raw| raw.split_whitespace().rev().find_map(numeric_zone_minutes))
        .unwrap_or_else(|| parsed_zone_minutes(date));
    let offset_seconds = i64::from(offset_minutes).strict_mul(60);
    Some(Timestamp {
        unix_seconds: date.to_timestamp_local().strict_sub(offset_seconds),
        offset_minutes,
    })
}

pub(crate) fn text_bodies<'a>(mail: &'a Mail<'a>) -> impl Iterator<Item = Cow<'a, str>> {
    (0..mail.text_body_count()).filter_map(move |position| mail.body_text(position))
}

pub(crate) fn html_bodies<'a>(mail: &'a Mail<'a>) -> impl Iterator<Item = Cow<'a, str>> {
    (0..mail.html_body_count()).filter_map(move |position| mail.body_html(position))
}

pub(crate) fn attachments<'a>(mail: &'a Mail<'a>) -> impl Iterator<Item = Attachment<'a>> {
    mail.attachments().map(|part| {
        let content_type = part.content_type();
        Attachment {
            filename: part.attachment_name(),
            media_type: content_type.map(mail_parser::ContentType::ctype),
            media_subtype: content_type.and_then(mail_parser::ContentType::subtype),
            data: attachment_bytes(part),
        }
    })
}

fn attachment_bytes<'a>(part: &'a MessagePart<'_>) -> &'a [u8] {
    part.message()
        .map_or_else(|| part.contents(), |nested| nested.raw_message.as_ref())
}

fn parsed_zone_minutes(date: &mail_parser::DateTime) -> i32 {
    let minutes = i32::from(date.tz_hour)
        .strict_mul(60)
        .strict_add(i32::from(date.tz_minute));
    if date.tz_before_gmt {
        minutes.strict_neg()
    } else {
        minutes
    }
}

fn numeric_zone_minutes(token: &str) -> Option<i32> {
    let (direction, digits) = token
        .strip_prefix('+')
        .map(|digits| (1, digits))
        .or_else(|| token.strip_prefix('-').map(|digits| (-1, digits)))?;
    if digits.len() != 4 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let (hours, minutes) = digits.split_at_checked(2)?;
    let hours = hours.parse::<i32>().ok().filter(|&hours| hours < 24)?;
    let minutes = minutes
        .parse::<i32>()
        .ok()
        .filter(|&minutes| minutes < 60)?;
    Some(
        hours
            .strict_mul(60)
            .strict_add(minutes)
            .strict_mul(direction),
    )
}

fn raw_header_value<'a>(raw: &'a [u8], header: &mail_parser::Header<'_>) -> Option<Cow<'a, str>> {
    let start = usize::try_from(header.offset_start).ok()?;
    let end = usize::try_from(header.offset_end).ok()?;
    Some(unfold(String::from_utf8_lossy(raw.get(start..end)?)))
}

pub(crate) fn unfold(text: Cow<'_, str>) -> Cow<'_, str> {
    if text.contains(['\r', '\n']) {
        return Cow::Owned(text.lines().collect::<String>().trim().to_owned());
    }
    match text {
        Cow::Borrowed(borrowed) => Cow::Borrowed(borrowed.trim()),
        Cow::Owned(owned) => Cow::Owned(owned.trim().to_owned()),
    }
}
