"""Header, address, date, body and attachment fields, and parity with stdlib."""

from datetime import UTC, datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

import pytest
from hypothesis import example, given

from mboxturbo import Mailbox, Message
from mboxturbo.tests.drafts import (
    DatedDraft,
    MailboxWriter,
    MessageDraft,
    dated_drafts,
    hostile_mailboxes,
    message_drafts,
)

pytestmark = pytest.mark.integration


def read_every_field(message: Message) -> list[object]:
    return [
        message.raw,
        message.subject,
        message.from_,
        message.to,
        message.cc,
        message.date,
        message.message_id,
        message.text,
        message.html,
        [(item.filename, item.content_type, item.data) for item in message.attachments],
        message.get('received'),
        message.get_all('x.trace'),
    ]


class TestHeaders:
    PLAIN = (
        b'From jane@example.com Mon Jan  1 00:00:00 2024\n'
        b'From: Jane Doe <jane@example.com>\n'
        b'To: a@example.org, B <b@example.org>\n'
        b'Cc: c@example.org\n'
        b'Subject: =?utf-8?q?caf=C3=A9?=\n'
        b'Date: Mon, 01 Jan 2024 00:00:00 -0500\n'
        b'Message-ID: <one@example.com>\n'
        b'Received: from mx1.example.com\n\tby mail.example.org; Mon, 1 Jan 2024\n'
        b'Received: from mx2.example.com by mx1.example.com\n'
        b'\n'
        b'first body\n'
        b'\n'
    )

    @pytest.fixture
    def message(self, mailbox_writer: MailboxWriter) -> Message:
        return Mailbox(mailbox_writer.write_raw(self.PLAIN))[0]

    def test_encoded_words_in_the_subject_are_decoded(self, message: Message) -> None:
        assert message.subject == 'café'

    def test_addresses_keep_display_names(self, message: Message) -> None:
        senders = [(address.name, address.email) for address in message.from_]
        recipients = [address.email for address in message.to]
        assert senders == [('Jane Doe', 'jane@example.com')]
        assert recipients == ['a@example.org', 'b@example.org']
        assert len(message.cc) == 1
        assert (
            repr(message.from_[0]) == "Address(name='Jane Doe', email='jane@example.com')"
        )

    def test_the_mbox_separator_is_not_mistaken_for_a_from_header(
        self, message: Message
    ) -> None:
        assert message.get('from') == 'Jane Doe <jane@example.com>'
        assert message.message_id == 'one@example.com'

    def test_repeated_headers_come_back_in_file_order_unfolded(
        self, message: Message
    ) -> None:
        assert message.get_all('RECEIVED') == [
            'from mx1.example.com\tby mail.example.org; Mon, 1 Jan 2024',
            'from mx2.example.com by mx1.example.com',
        ]
        assert message.get('x-absent') is None

    def test_the_date_is_aware_and_keeps_its_own_offset(self, message: Message) -> None:
        minus_five = timezone(timedelta(hours=-5))
        assert message.date == datetime(2024, 1, 1, 5, tzinfo=UTC)
        assert message.date == datetime(2024, 1, 1, tzinfo=minus_five)
        assert message.date is not None
        assert message.date.utcoffset() == timedelta(hours=-5)


class TestBodies:
    MULTIPART = (
        b'From bob@example.com Tue Jan  2 00:00:00 2024\n'
        b'From: bob@example.com\n'
        b'Subject: report\n'
        b'MIME-Version: 1.0\n'
        b'Content-Type: multipart/mixed; boundary="B"\n'
        b'\n'
        b'--B\n'
        b'Content-Type: text/html\n'
        b'\n'
        b'<p>hello</p>\n'
        b'--B\n'
        b'Content-Type: application/octet-stream; name="x.bin"\n'
        b'Content-Disposition: attachment; filename="x.bin"\n'
        b'Content-Transfer-Encoding: base64\n'
        b'\n'
        b'AAEC\n'
        b'--B--\n'
        b'\n'
    )

    @pytest.fixture
    def message(self, mailbox_writer: MailboxWriter) -> Message:
        return Mailbox(mailbox_writer.write_raw(self.MULTIPART))[0]

    def test_attachments_are_decoded_with_name_and_type(self, message: Message) -> None:
        (attachment,) = message.attachments
        assert attachment.filename == 'x.bin'
        assert attachment.content_type == 'application/octet-stream'
        assert attachment.data == b'\x00\x01\x02'
        assert repr(attachment) == (
            "Attachment(filename='x.bin', "
            "content_type='application/octet-stream', size=3)"
        )

    def test_html_only_messages_offer_html_and_derived_text(
        self, message: Message
    ) -> None:
        assert '<p>hello</p>' in message.html[0]
        assert 'hello' in message.text[0]


class TestStdlibParity:
    @given(draft=message_drafts)
    def test_subject_and_sender_match_what_the_stdlib_parses(
        self, mailbox_writer: MailboxWriter, draft: MessageDraft
    ) -> None:
        message = Mailbox(mailbox_writer.write([draft]))[0]
        stdlib = message.to_email_message()
        assert message.subject == stdlib['Subject']
        assert [address.email for address in message.from_] == [draft.sender]
        assert stdlib.get_unixfrom() == f'From {draft.sender} Mon Jan  1 00:00:00 2024'


class TestDates:
    @pytest.mark.regression
    @given(draft=dated_drafts)
    @example(draft=DatedDraft(date='Mon, 01 Jan 2024 12:00:00 +1300'))
    @example(draft=DatedDraft(date='Mon, 01 Jan 2024 12:00:00 +1400'))
    def test_dates_match_the_stdlib_including_zones_past_twelve_hours(
        self, mailbox_writer: MailboxWriter, draft: DatedDraft
    ) -> None:
        expected = parsedate_to_datetime(draft.date)
        parsed = Mailbox(mailbox_writer.write_raw(draft.render()))[0].date
        assert parsed == expected
        assert parsed is not None
        assert parsed.utcoffset() == expected.utcoffset()


class TestHostileInput:
    @pytest.mark.regression
    @given(contents=hostile_mailboxes)
    @example(contents=b'From a\nSubject: s\nReceived:\n\t')
    @example(contents=b'From a\nSubject: s\nReceived: from x;\n\t')
    @example(contents=b'From a\nContent-Type: message/rfc822\n\nno headers here\n')
    def test_every_field_answers_on_hostile_input(
        self, mailbox_writer: MailboxWriter, contents: bytes
    ) -> None:
        mailbox = Mailbox(mailbox_writer.write_raw(contents))
        fields = [read_every_field(message) for message in mailbox]
        batched = [
            read_every_field(message) for batch in mailbox.batches(4) for message in batch
        ]
        assert fields == batched

    def test_header_names_containing_dots_are_found(
        self, mailbox_writer: MailboxWriter
    ) -> None:
        contents = b'From a\nX.Trace: route\nSubject: s\n\nbody\n'
        assert Mailbox(mailbox_writer.write_raw(contents))[0].get('X.Trace') == 'route'
