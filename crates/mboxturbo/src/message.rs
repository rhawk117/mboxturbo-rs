//! One message: raw bytes borrowed from the mailbox mapping, parsed once on first use.

use std::borrow::Cow;
use std::ops::Range;
use std::sync::{Arc, OnceLock};

use memmap2::Mmap;

use crate::fields::{self, FULL_PARSER, contain_parser_panic, strip_separator};
use cell::Parsed;

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
        strip_separator(self.bytes())
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
        fields::addresses(self.head().and_then(mail_parser::Message::from))
    }

    /// Every address in `To:`.
    pub fn to(&self) -> impl Iterator<Item = Address<'_>> {
        fields::addresses(self.head().and_then(mail_parser::Message::to))
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
        self.head()
            .into_iter()
            .flat_map(move |mail| fields::header_values(mail, wanted.clone()))
    }

    /// Plain-text bodies; an HTML-only message yields its HTML converted to text.
    pub fn text_bodies(&self) -> impl Iterator<Item = Cow<'_, str>> {
        self.whole().into_iter().flat_map(fields::text_bodies)
    }

    /// HTML bodies; a text-only message yields its text converted to HTML.
    pub fn html_bodies(&self) -> impl Iterator<Item = Cow<'_, str>> {
        self.whole().into_iter().flat_map(fields::html_bodies)
    }

    /// Every attachment, decoded.
    pub fn attachments(&self) -> impl Iterator<Item = Attachment<'_>> {
        self.whole().into_iter().flat_map(fields::attachments)
    }

    fn head(&self) -> Option<&mail_parser::Message<'_>> {
        self.whole
            .get()
            .unwrap_or_else(|| {
                self.head.get_or_init(|| {
                    Parsed::new(self.source.clone(), |source| {
                        contain_parser_panic(|| FULL_PARSER.parse_headers(source.rfc822()))
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

    use crate::Mailbox;
    use crate::fields::unfold;

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
