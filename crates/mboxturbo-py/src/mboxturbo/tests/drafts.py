"""Message drafts rendered to mbox bytes, and Hypothesis strategies for them."""

import string
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path
from uuid import uuid4

from hypothesis import strategies as st

SEPARATOR = 'From '


def escape_separator(line: str) -> str:
    return f'>{line}' if line.startswith(SEPARATOR) else line


@dataclass(slots=True, kw_only=True, frozen=True)
class MessageDraft:
    sender: str
    subject: str
    body: Sequence[str]

    def render(self) -> bytes:
        lines = [
            f'From {self.sender} Mon Jan  1 00:00:00 2024',
            f'From: <{self.sender}>',
            f'Subject: {self.subject}',
            '',
            *map(escape_separator, self.body),
            '',
            '',
        ]
        return '\n'.join(lines).encode()


@dataclass(slots=True, kw_only=True, frozen=True)
class DatedDraft:
    date: str

    def render(self) -> bytes:
        lines = [
            'From a@example.com Mon Jan  1 00:00:00 2024',
            f'Date: {self.date}',
            '',
            'b',
            '',
        ]
        return '\n'.join(lines).encode()


def zoned_date(unix_seconds: int, quarter_hours: int) -> str:
    zone = timezone(timedelta(minutes=quarter_hours * 15))
    return format_datetime(datetime.fromtimestamp(unix_seconds, tz=zone))


@dataclass(slots=True, kw_only=True, frozen=True)
class MailboxWriter:
    directory: Path

    def write(self, drafts: Sequence[MessageDraft]) -> Path:
        path = self.directory.joinpath(f'{uuid4().hex}.mbox')
        path.write_bytes(b''.join(draft.render() for draft in drafts))
        return path

    def write_raw(self, contents: bytes) -> Path:
        path = self.directory.joinpath(f'{uuid4().hex}.mbox')
        path.write_bytes(contents)
        return path

    def index_path(self) -> Path:
        return self.directory.joinpath(f'{uuid4().hex}.mbxidx')


words = st.text(alphabet=string.ascii_letters + string.digits, min_size=1, max_size=10)
tricky_words = st.sampled_from(['From', 'from', 'From:', '>From', 'Fro', 'm'])
body_lines = st.lists(tricky_words | words, max_size=6).map(' '.join)
message_drafts = st.builds(
    MessageDraft,
    sender=st.from_regex(r'[a-z]{1,8}@example\.com', fullmatch=True),
    subject=st.lists(words, min_size=1, max_size=4).map(' '.join),
    body=st.lists(body_lines, max_size=5),
)
mailbox_drafts = st.lists(message_drafts, max_size=12)
dated_drafts = st.builds(
    DatedDraft,
    date=st.builds(
        zoned_date,
        unix_seconds=st.integers(0, 4_102_444_800),
        quarter_hours=st.integers(-48, 56),
    ),
)
hostile_fragments = st.sampled_from([
    b'From a@example.com Mon Jan  1 00:00:00 2024\n',
    b'Received:\n\t',
    b'Received: from x;\n\t',
    b'Content-Type: message/rfc822\n',
    b'Content-Type: multipart/mixed; boundary="B"\n',
    b'Content-Transfer-Encoding: base64\n',
    b'--B\n',
    b'--B--\n',
    b'Date: Mon, 01 Jan 2024 12:00:00 +1400\n',
    b'X.Trace: route\n',
    b'\n',
    b'AAEC\n',
])
hostile_mailboxes = st.lists(hostile_fragments | st.binary(max_size=12), max_size=24).map(
    b''.join
)
