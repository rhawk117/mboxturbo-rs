//! One message: raw bytes borrowed from the mailbox mapping, parsed once on first use.

use std::borrow::Cow;
use std::ops::Range;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, LazyLock, OnceLock};

use mail_parser::{HeaderName, MessageParser, MessagePart, MimeHeaders};
use memmap2::Mmap;

use cell::Parsed;

const SEPARATOR: &[u8] = b"From ";

static PARSER: LazyLock<MessageParser> = LazyLock::new(builtin_table_with_raw_received);

fn builtin_table_with_raw_received() -> MessageParser {
    MessageParser::new()
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

fn contain_parser_panic<'a>(
    parse: impl FnOnce() -> Option<mail_parser::Message<'a>>,
) -> Option<mail_parser::Message<'a>> {
    catch_unwind(AssertUnwindSafe(parse)).ok().flatten()
}

#[derive(Debug, Clone)]
struct Source {
    contents: Arc<Mmap>,
    span: Range<usize>,
}

impl Source {
    fn bytes(&self) -> &[u8] {
        self.contents.get(self.span.clone()).unwrap_or_default()
    }

    fn rfc822(&self) -> &[u8] {
        let bytes = self.bytes();
        if !bytes.starts_with(SEPARATOR) {
            return bytes;
        }
        bytes
            .iter()
            .position(|&byte| byte == b'\n')
            .and_then(|newline| bytes.get(newline.strict_add(1)..))
            .unwrap_or_default()
    }
}

mod cell {
    #![expect(
        clippy::mem_forget,
        reason = "self_cell's expansion forgets its guard on purpose once ownership has moved"
    )]

    use self_cell::self_cell;

    use super::Source;

    type ParsedMail<'a> = Option<mail_parser::Message<'a>>;

    self_cell!(
        pub(super) struct Parsed {
            owner: Source,

            #[covariant]
            dependent: ParsedMail,
        }

        impl {Debug}
    );
}

/// A mailbox address as written in a header: either part may be missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Address<'a> {
    /// Display name, such as `Jane Doe`.
    pub name: Option<&'a str>,
    /// Address, such as `jane@example.com`.
    pub email: Option<&'a str>,
}

/// A `Date:` header resolved to an instant plus the offset it was written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Timestamp {
    /// Seconds since the Unix epoch, in UTC.
    pub unix_seconds: i64,
    /// The header's UTC offset in minutes; `-300` for `-0500`.
    pub offset_minutes: i32,
}

/// A decoded attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attachment<'a> {
    /// File name from `Content-Disposition` or `Content-Type`.
    pub filename: Option<&'a str>,
    /// Top-level media type, such as `application`.
    pub media_type: Option<&'a str>,
    /// Media subtype, such as `pdf`.
    pub media_subtype: Option<&'a str>,
    /// Contents with the transfer encoding (base64, quoted-printable) removed.
    pub data: &'a [u8],
}

impl Attachment<'_> {
    /// The full media type, such as `application/pdf`.
    #[must_use]
    pub fn content_type(&self) -> Option<String> {
        let media_type = self.media_type?;
        Some(self.media_subtype.map_or_else(
            || media_type.to_owned(),
            |subtype| format!("{media_type}/{subtype}"),
        ))
    }
}

/// One message from a [`Mailbox`](crate::Mailbox).
///
/// It shares ownership of the mapping, so it stays valid after the mailbox is dropped. Fields
/// parse on first access, borrowing from the mapping without copying: header fields parse the
/// header block only, and bodies or attachments trigger the full MIME parse.
#[derive(Debug)]
pub struct Message {
    source: Source,
    head: OnceLock<Parsed>,
    whole: OnceLock<Parsed>,
}

impl Message {
    pub(crate) const fn new(contents: Arc<Mmap>, span: Range<usize>) -> Self {
        Self {
            source: Source { contents, span },
            head: OnceLock::new(),
            whole: OnceLock::new(),
        }
    }

    /// Raw bytes exactly as stored, including the mbox `From ` separator line.
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        self.source.bytes()
    }

    /// Parses the whole message now, bodies and attachments included, rather than on first
    /// access; returns whether any MIME part was found.
    pub fn parse(&self) -> bool {
        self.whole().is_some()
    }

    /// Decoded `Subject:`.
    #[must_use]
    pub fn subject(&self) -> Option<&str> {
        self.head()?.subject()
    }

    /// Every address in `From:`.
    pub fn from(&self) -> impl Iterator<Item = Address<'_>> {
        self.addresses(mail_parser::Message::from)
    }

    /// Every address in `To:`.
    pub fn to(&self) -> impl Iterator<Item = Address<'_>> {
        self.addresses(mail_parser::Message::to)
    }

    /// Every address in `Cc:`.
    pub fn cc(&self) -> impl Iterator<Item = Address<'_>> {
        self.addresses(mail_parser::Message::cc)
    }

    /// `Date:` resolved to UTC, or `None` when absent or invalid. A numeric zone such as
    /// `+1300` is read from the header itself, so offsets past twelve hours stay exact.
    #[must_use]
    pub fn date(&self) -> Option<Timestamp> {
        let date = self.head()?.date().filter(|date| date.is_valid())?;
        let offset_minutes = self
            .header_values("date")
            .last()
            .and_then(|raw| raw.split_whitespace().rev().find_map(numeric_zone_minutes))
            .unwrap_or_else(|| parsed_zone_minutes(date));
        let offset_seconds = i64::from(offset_minutes).strict_mul(60);
        Some(Timestamp {
            unix_seconds: date.to_timestamp_local().strict_sub(offset_seconds),
            offset_minutes,
        })
    }

    /// `Message-ID:` without the angle brackets.
    #[must_use]
    pub fn message_id(&self) -> Option<&str> {
        self.head()?.message_id()
    }

    /// First value of the header called `name` (any case), unfolded onto one line.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<Cow<'_, str>> {
        self.header_values(name).next()
    }

    /// Every value of the header called `name` (any case) in file order, unfolded onto one
    /// line each. Values are raw: encoded words such as `=?utf-8?...?=` are left as written.
    pub fn header_values<'a>(&'a self, name: &str) -> impl Iterator<Item = Cow<'a, str>> + use<'a> {
        let wanted = name.to_owned();
        self.head().into_iter().flat_map(move |mail| {
            let raw = mail.raw_message();
            let wanted = wanted.clone();
            mail.headers()
                .iter()
                .filter(move |header| header.name.as_str().eq_ignore_ascii_case(&wanted))
                .filter_map(move |header| raw_header_value(raw, header))
        })
    }

    /// Plain-text bodies; an HTML-only message yields its HTML converted to text.
    pub fn text_bodies(&self) -> impl Iterator<Item = Cow<'_, str>> {
        self.whole().into_iter().flat_map(|mail| {
            (0..mail.text_body_count()).filter_map(move |position| mail.body_text(position))
        })
    }

    /// HTML bodies; a text-only message yields its text converted to HTML.
    pub fn html_bodies(&self) -> impl Iterator<Item = Cow<'_, str>> {
        self.whole().into_iter().flat_map(|mail| {
            (0..mail.html_body_count()).filter_map(move |position| mail.body_html(position))
        })
    }

    /// Every attachment, decoded.
    pub fn attachments(&self) -> impl Iterator<Item = Attachment<'_>> {
        self.whole().into_iter().flat_map(|mail| {
            mail.attachments().map(|part| {
                let content_type = part.content_type();
                Attachment {
                    filename: part.attachment_name(),
                    media_type: content_type.map(mail_parser::ContentType::ctype),
                    media_subtype: content_type.and_then(mail_parser::ContentType::subtype),
                    data: attachment_bytes(part),
                }
            })
        })
    }

    fn head(&self) -> Option<&mail_parser::Message<'_>> {
        self.whole
            .get()
            .unwrap_or_else(|| {
                self.head.get_or_init(|| {
                    Parsed::new(self.source.clone(), |source| {
                        contain_parser_panic(|| PARSER.parse_headers(source.rfc822()))
                    })
                })
            })
            .borrow_dependent()
            .as_ref()
    }

    fn whole(&self) -> Option<&mail_parser::Message<'_>> {
        self.whole
            .get_or_init(|| {
                Parsed::new(self.source.clone(), |source| {
                    contain_parser_panic(|| PARSER.parse(source.rfc822()))
                })
            })
            .borrow_dependent()
            .as_ref()
    }

    fn addresses<'a>(
        &'a self,
        field: fn(&'a mail_parser::Message<'a>) -> Option<&'a mail_parser::Address<'a>>,
    ) -> impl Iterator<Item = Address<'a>> {
        self.head()
            .and_then(field)
            .into_iter()
            .flat_map(mail_parser::Address::iter)
            .map(|addr| Address {
                name: addr.name.as_deref(),
                email: addr.address.as_deref(),
            })
    }
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

fn unfold(text: Cow<'_, str>) -> Cow<'_, str> {
    if text.contains(['\r', '\n']) {
        return Cow::Owned(text.lines().collect::<String>().trim().to_owned());
    }
    match text {
        Cow::Borrowed(borrowed) => Cow::Borrowed(borrowed.trim()),
        Cow::Owned(owned) => Cow::Owned(owned.trim().to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::fs;

    use super::unfold;
    use crate::Mailbox;

    const MESSAGE: &[u8] = b"From a@example.com Mon Jan  1 00:00:00 2024\n\
From: A <a@example.com>\nSubject: lazy\nMessage-ID: <m@example.com>\n\
Content-Type: multipart/mixed; boundary=\"B\"\n\n--B\nContent-Type: text/plain\n\nhi\n\
--B\nContent-Type: application/octet-stream\nContent-Transfer-Encoding: base64\n\nAAEC\n--B--\n";

    fn mailbox() -> (tempfile::TempDir, Mailbox) {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("lazy.mbox");
        fs::write(&path, MESSAGE).expect("write");
        let mailbox = Mailbox::open(&path).expect("open");
        (directory, mailbox)
    }

    #[test]
    fn header_fields_never_trigger_the_full_parse() {
        let (_directory, mailbox) = mailbox();
        let message = mailbox.message(0).expect("message");
        assert_eq!(
            message.subject(),
            Some("lazy"),
            "subject from the header tier"
        );
        assert_eq!(
            message.header("message-id").as_deref(),
            Some("<m@example.com>"),
            "raw"
        );
        assert!(message.whole.get().is_none(), "bodies were not decoded");
        assert_eq!(
            message.attachments().count(),
            1,
            "attachment access parses the rest"
        );
        assert!(
            message.whole.get().is_some(),
            "full parse happened on demand"
        );
    }

    #[test]
    fn both_tiers_agree_on_header_fields() {
        let (_directory, mailbox) = mailbox();
        let headers_only = mailbox.message(0).expect("message");
        let parsed_fully = mailbox.message(0).expect("message");
        assert!(parsed_fully.parse(), "full parse succeeds");
        assert_eq!(headers_only.subject(), parsed_fully.subject(), "subject");
        assert_eq!(
            headers_only.message_id(),
            parsed_fully.message_id(),
            "message id"
        );
        assert!(
            headers_only.from().eq(parsed_fully.from()),
            "from addresses"
        );
        assert!(
            headers_only
                .header_values("from")
                .eq(parsed_fully.header_values("from")),
            "raw header values"
        );
    }

    #[test]
    fn unfolding_joins_continuation_lines_and_keeps_their_whitespace() {
        let folded = Cow::Borrowed(" from a.example\r\n\tby b.example; Mon\n");
        assert_eq!(
            unfold(folded),
            "from a.example\tby b.example; Mon",
            "RFC 5322 unfolding"
        );
    }

    #[test]
    fn unfolding_borrows_when_nothing_needs_joining() {
        assert!(
            matches!(unfold(Cow::Borrowed(" value ")), Cow::Borrowed("value")),
            "no copy"
        );
    }
}
