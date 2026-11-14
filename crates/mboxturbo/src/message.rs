//! One message: raw bytes borrowed from the mailbox mapping, parsed once on first use.

/// Owner and dependent in one value: a parsed message together with the bytes it borrows.
mod cell {
    #![expect(
        clippy::mem_forget,
        reason = "self_cell's expansion forgets its guard on purpose once ownership has moved"
    )]

    use self_cell::self_cell;

    use super::Source;

    /// The parse result: `None` when the parser found no message.
    type ParsedMail<'text> = Option<mail_parser::Message<'text>>;

    self_cell!(
        pub(super) struct Parsed {
            owner: Source,

            #[covariant]
            dependent: ParsedMail,
        }

        impl {Debug}
    );
}

use std::borrow::Cow;
use std::ops::Range;
use std::sync::{Arc, OnceLock};

use cell::Parsed;
use memmap2::Mmap;

use crate::fields::{self, FULL_PARSER, contain_parser_panic, strip_separator};

/// A message's bytes: its span within the shared mapping.
#[derive(Debug, Clone)]
struct Source {
    /// The mailbox mapping, shared with every message cut from it.
    contents: Arc<Mmap>,
    /// Where the message lies in `contents`, separator line included.
    span: Range<usize>,
}

impl Source {
    /// The message's bytes exactly as stored, separator line included.
    #[expect(
        clippy::expect_used,
        reason = "`span` comes from the validated index, which keeps every span inside the \
                  mapping (see Mailbox::rows), so `contents` always has these bytes"
    )]
    fn bytes(&self) -> &[u8] {
        self.contents
            .get(self.span.clone())
            .expect("a span from the validated index lies inside the mapping")
    }

    /// The RFC 822 content: the bytes without the `From ` separator line.
    fn rfc822(&self) -> &[u8] {
        strip_separator(self.bytes())
    }
}

/// A mailbox address as written in a header: either part may be missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Address<'mail> {
    /// Address, such as `jane@example.com`.
    pub email: Option<&'mail str>,
    /// Display name, such as `Jane Doe`.
    pub name: Option<&'mail str>,
}

/// A `Date:` header resolved to an instant plus the offset it was written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Timestamp {
    /// The header's UTC offset in minutes; `-300` for `-0500`.
    pub offset_minutes: i32,
    /// Seconds since the Unix epoch, in UTC.
    pub unix_seconds: i64,
}

/// A decoded attachment.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Attachment<'mail> {
    /// Contents with the transfer encoding (base64, quoted-printable) removed.
    pub data: Cow<'mail, [u8]>,
    /// File name from `Content-Disposition` or `Content-Type`.
    pub filename: Option<&'mail str>,
    /// Media subtype, such as `pdf`.
    pub media_subtype: Option<&'mail str>,
    /// Top-level media type, such as `application`.
    pub media_type: Option<&'mail str>,
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
    /// The header-only parse, filled on first header access.
    head: OnceLock<Parsed>,
    /// This message's bytes.
    source: Source,
    /// The full MIME parse, filled on first body or attachment access.
    whole: OnceLock<Parsed>,
}

impl Message {
    /// Every attachment, decoded.
    pub fn attachments(&self) -> impl Iterator<Item = Attachment<'_>> {
        self.whole().into_iter().flat_map(fields::attachments)
    }

    /// Every address in `Cc:`.
    pub fn cc(&self) -> impl Iterator<Item = Address<'_>> {
        fields::addresses(self.head().and_then(mail_parser::Message::cc))
    }

    /// `Date:` resolved to UTC, or `None` when absent or invalid. A numeric zone such as
    /// `+1300` is read from the header itself, so offsets past twelve hours stay exact.
    #[must_use]
    pub fn date(&self) -> Option<Timestamp> {
        self.head().and_then(fields::date)
    }

    /// Every address in `From:`.
    pub fn from(&self) -> impl Iterator<Item = Address<'_>> {
        fields::addresses(self.head().and_then(mail_parser::Message::from))
    }

    /// The parsed message to read header fields from: the full parse when it already produced a
    /// message, else the header-only parse, made on first use. `None` when neither parsed.
    fn head(&self) -> Option<&mail_parser::Message<'_>> {
        self.whole
            .get()
            .and_then(|parsed| parsed.borrow_dependent().as_ref())
            .or_else(|| {
                self.head
                    .get_or_init(|| self.parse_head())
                    .borrow_dependent()
                    .as_ref()
            })
    }

    /// First value of the header called `name` (any case), unfolded onto one line.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<Cow<'_, str>> {
        self.header_values(name).next()
    }

    /// Every value of the header called `name` (any case) in file order, unfolded onto one
    /// line each. Values are raw: encoded words such as `=?utf-8?...?=` are left as written.
    /// A value is borrowed unless it was folded or held invalid UTF-8. The iterator borrows `name`.
    pub fn header_values<'message>(
        &'message self,
        name: &str,
    ) -> impl Iterator<Item = Cow<'message, str>> {
        self.head()
            .into_iter()
            .flat_map(move |mail| fields::header_values(mail, name))
    }

    /// HTML bodies; a text-only message yields its text converted to HTML.
    pub fn html_bodies(&self) -> impl Iterator<Item = Cow<'_, str>> {
        self.whole().into_iter().flat_map(fields::html_bodies)
    }

    /// `Message-ID:` without the angle brackets.
    #[must_use]
    pub fn message_id(&self) -> Option<&str> {
        self.head()?.message_id()
    }

    /// A message over `span` of `contents`; `span` must come from the validated index.
    pub(crate) const fn new(contents: Arc<Mmap>, span: Range<usize>) -> Self {
        Self {
            source: Source { contents, span },
            head: OnceLock::new(),
            whole: OnceLock::new(),
        }
    }

    /// Parses the whole message now, bodies and attachments included, rather than on first
    /// access; returns whether any MIME part was found. `false` also covers a parser panic that
    /// was contained.
    pub fn parse(&self) -> bool {
        self.whole().is_some()
    }

    /// Parses the header block alone.
    fn parse_head(&self) -> Parsed {
        Parsed::new(self.source.clone(), |source| {
            contain_parser_panic(|| FULL_PARSER.parse_headers(source.rfc822()))
        })
    }

    /// Raw bytes exactly as stored, including the mbox `From ` separator line.
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        self.source.bytes()
    }

    /// Decoded `Subject:`.
    #[must_use]
    pub fn subject(&self) -> Option<&str> {
        self.head()?.subject()
    }

    /// Plain-text bodies; an HTML-only message yields its HTML converted to text.
    pub fn text_bodies(&self) -> impl Iterator<Item = Cow<'_, str>> {
        self.whole().into_iter().flat_map(fields::text_bodies)
    }

    /// Every address in `To:`.
    pub fn to(&self) -> impl Iterator<Item = Address<'_>> {
        fields::addresses(self.head().and_then(mail_parser::Message::to))
    }

    /// The full MIME parse, made on first use. `None` when nothing parsed.
    fn whole(&self) -> Option<&mail_parser::Message<'_>> {
        self.whole
            .get_or_init(|| {
                Parsed::new(self.source.clone(), |source| {
                    contain_parser_panic(|| FULL_PARSER.parse(source.rfc822()))
                })
            })
            .borrow_dependent()
            .as_ref()
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::fs;

    use super::Parsed;
    use crate::Mailbox;
    use crate::fields::unfold;

    const MESSAGE: &[u8] = b"From a@example.com Mon Jan  1 00:00:00 2024\n\
From: A <a@example.com>\nSubject: lazy\nMessage-ID: <m@example.com>\n\
Content-Type: multipart/mixed; boundary=\"B\"\n\n--B\nContent-Type: text/plain\n\nhi\n\
--B\nContent-Type: application/octet-stream\nContent-Transfer-Encoding: base64\n\nAAEC\n--B--\n";

    fn mailbox() -> (tempfile::TempDir, Mailbox) {
        let directory = tempfile::tempdir().expect("temp directory is created");
        let path = directory.path().join("lazy.mbox");
        fs::write(&path, MESSAGE).expect("fixture mbox is written");
        let mailbox = Mailbox::open(&path).expect("fixture mbox opens");
        (directory, mailbox)
    }

    #[test]
    fn header_fields_never_trigger_the_full_parse() {
        let (_directory, mailbox) = mailbox();
        let message = mailbox
            .message(0)
            .expect("the fixture holds a first message");
        assert_eq!(
            message.subject(),
            Some("lazy"),
            "the subject is read from the header-only parse"
        );
        assert_eq!(
            message.header("message-id").as_deref(),
            Some("<m@example.com>"),
            "the message id is read raw from the header-only parse"
        );
        assert!(
            message.whole.get().is_none(),
            "header access leaves the bodies undecoded"
        );
        assert_eq!(
            message.attachments().count(),
            1,
            "attachment access runs the full parse and finds the one attachment"
        );
        assert!(
            message.whole.get().is_some(),
            "attachment access filled the full-parse cell"
        );
    }

    #[test]
    fn both_tiers_agree_on_header_fields() {
        let (_directory, mailbox) = mailbox();
        let headers_only = mailbox
            .message(0)
            .expect("the fixture holds a first message");
        let parsed_fully = mailbox
            .message(0)
            .expect("the fixture holds a first message");
        assert!(parsed_fully.parse(), "the fixture parses fully");
        assert_eq!(
            headers_only.subject(),
            parsed_fully.subject(),
            "both tiers read the same subject"
        );
        assert_eq!(
            headers_only.message_id(),
            parsed_fully.message_id(),
            "both tiers read the same message id"
        );
        assert!(
            headers_only.from().eq(parsed_fully.from()),
            "both tiers read the same from addresses"
        );
        assert!(
            headers_only
                .header_values("from")
                .eq(parsed_fully.header_values("from")),
            "both tiers read the same raw From values"
        );
    }

    #[test]
    fn a_failed_full_parse_falls_back_to_the_header_only_parse() {
        let (_directory, mailbox) = mailbox();
        let message = mailbox.message(0).expect("fixture has one message");
        let seeded = message
            .whole
            .set(Parsed::new(message.source.clone(), |_| None))
            .is_ok();
        assert!(seeded, "the full-parse cell was empty before seeding");
        assert!(
            message.whole().is_none(),
            "the seeded full parse yields no message"
        );
        assert_eq!(
            message.subject(),
            Some("lazy"),
            "header accessors fall back to the header-only parse when the full parse yields none"
        );
        assert_eq!(
            message.message_id(),
            Some("m@example.com"),
            "the message id also falls back to the header-only parse"
        );
    }

    #[test]
    fn a_successful_full_parse_leaves_the_subject_unchanged() {
        let (_directory, mailbox) = mailbox();
        let message = mailbox.message(0).expect("fixture has one message");
        let before = message.subject().map(str::to_owned);
        assert!(message.parse(), "the fixture has MIME parts");
        assert_eq!(
            message.subject(),
            before.as_deref(),
            "a successful full parse does not change the subject"
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
            "a value with no folded lines is trimmed without allocating a copy"
        );
    }
}
