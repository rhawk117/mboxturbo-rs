"""Columnar selections: Arrow consumers, Parquet output and agreement with Message."""

import hashlib
import sysconfig
import threading
import time
from collections.abc import Sequence
from datetime import timedelta
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest
from hypothesis import example, given
from hypothesis import strategies as st

from mboxturbo import Mailbox, Message, Selection
from mboxturbo.tests.drafts import (
    MailboxWriter,
    MessageDraft,
    hostile_mailboxes,
    mailbox_drafts,
)

pytestmark = pytest.mark.integration


def expected_header_row(
    message: Message, position: int, offset: int
) -> dict[str, object]:
    return {
        'position': position,
        'offset': offset,
        'size': len(message.raw),
        'subject': message.subject,
        'from': [address.email for address in message.from_],
        'received': message.get_all('received'),
    }


class TestSelection:
    HEADER_COLUMNS = ('position', 'offset', 'size', 'subject', 'from', 'received')
    MULTIPART = (
        b'From bob@example.com Tue Jan  2 00:00:00 2024\n'
        b'From: bob@example.com\n'
        b'Date: Mon, 01 Jan 2024 12:00:00 +1300\n'
        b'X-Mailer: forged\n'
        b'Content-Type: multipart/mixed; boundary="B"\n'
        b'\n'
        b'--B\n'
        b'Content-Type: text/plain\n'
        b'\n'
        b'hello\n'
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
    def multipart(self, mailbox_writer: MailboxWriter) -> Mailbox:
        return Mailbox(mailbox_writer.write_raw(self.MULTIPART))

    @given(drafts=mailbox_drafts)
    def test_header_columns_agree_with_the_message_api(
        self, mailbox_writer: MailboxWriter, drafts: Sequence[MessageDraft]
    ) -> None:
        mailbox = Mailbox(mailbox_writer.write(drafts))
        offsets = [0, *(len(draft.render()) for draft in drafts)]
        starts = [sum(offsets[: index + 1]) for index in range(len(drafts))]
        expected = [
            expected_header_row(message, position, starts[position])
            for position, message in enumerate(mailbox)
        ]
        assert pa.table(mailbox.select(self.HEADER_COLUMNS)).to_pylist() == expected

    def test_body_and_attachment_columns_decode_and_hash(
        self, multipart: Mailbox
    ) -> None:
        columns = ['text', 'attachment_names', 'attachment_types', 'attachment_sizes']
        row = pa.table(multipart.select([*columns, 'attachment_sha256'])).to_pylist()[0]
        assert row == {
            'text': 'hello',
            'attachment_names': ['x.bin'],
            'attachment_types': ['application/octet-stream'],
            'attachment_sizes': [3],
            'attachment_sha256': [hashlib.sha256(b'\x00\x01\x02').hexdigest()],
        }

    def test_dates_are_utc_timestamps_with_the_original_offset(
        self, multipart: Mailbox
    ) -> None:
        row = pa.table(multipart.select(['date', 'date_offset_minutes'])).to_pylist()[0]
        assert row['date'] == multipart[0].date
        assert row['date'].utcoffset() == timedelta(0)
        assert row['date_offset_minutes'] == 13 * 60

    def test_any_header_can_be_selected_by_name(self, multipart: Mailbox) -> None:
        table = pa.table(multipart.select(['header:x-mailer', 'header:X-Absent']))
        assert table.column_names == ['header:x-mailer', 'header:X-Absent']
        assert table.to_pylist() == [
            {'header:x-mailer': ['forged'], 'header:X-Absent': []}
        ]

    def test_defaults_cover_every_header_column_and_skip_bodies(
        self, multipart: Mailbox
    ) -> None:
        columns = multipart.select().columns
        assert 'received' in columns
        assert 'authentication_results' in columns
        assert 'text' not in columns
        assert 'attachment_sha256' not in columns

    @given(drafts=mailbox_drafts)
    def test_the_raw_column_equals_each_messages_bytes(
        self, mailbox_writer: MailboxWriter, drafts: Sequence[MessageDraft]
    ) -> None:
        mailbox = Mailbox(mailbox_writer.write(drafts))
        table = pa.table(mailbox.select(['raw']))
        assert table.column('raw').to_pylist() == [message.raw for message in mailbox]


class TestConsumers:
    SAMPLE = (MessageDraft(sender='a@example.com', subject='s', body=['b']),)

    @pytest.fixture
    def mailbox(self, mailbox_writer: MailboxWriter) -> Mailbox:
        return Mailbox(mailbox_writer.write(self.SAMPLE))

    def test_a_selection_can_be_read_more_than_once(self, mailbox: Mailbox) -> None:
        selection = mailbox.select(['position', 'subject'])
        assert pa.table(selection) == pa.table(selection)

    def test_unknown_columns_name_the_catalogue(self, mailbox: Mailbox) -> None:
        with pytest.raises(
            ValueError, match="unknown column 'subjekt'; expected one of position"
        ):
            mailbox.select(['subjekt'])

    def test_a_batch_size_of_zero_is_rejected(self, mailbox: Mailbox) -> None:
        with pytest.raises(ValueError, match='batch size must be positive'):
            mailbox.select(batch_size=0)


class TestParquet:
    ALL_COLUMNS = (
        'position', 'offset', 'size', 'from', 'to', 'cc', 'reply_to', 'subject', 'date',
        'date_offset_minutes', 'message_id', 'received', 'authentication_results',
        'received_spf', 'dkim_signature', 'return_path', 'text', 'html',
        'attachment_names', 'attachment_types', 'attachment_sizes', 'attachment_sha256',
    )  # fmt: skip

    @given(drafts=mailbox_drafts, batch_size=st.integers(1, 5))
    def test_parquet_holds_exactly_what_the_stream_yields(
        self,
        mailbox_writer: MailboxWriter,
        drafts: Sequence[MessageDraft],
        batch_size: int,
    ) -> None:
        selection = Mailbox(mailbox_writer.write(drafts)).select(
            self.ALL_COLUMNS, batch_size=batch_size
        )
        target = mailbox_writer.index_path().with_suffix('.parquet')
        assert selection.to_parquet(target) == len(drafts)
        written, streamed = pq.read_table(target), pa.table(selection)
        assert written.schema.remove_metadata() == streamed.schema
        assert written.to_pylist() == streamed.to_pylist()

    @pytest.mark.parametrize('compression', ['zstd', 'snappy', 'none'])
    def test_every_compression_writes_a_readable_file(
        self, mailbox_writer: MailboxWriter, compression: str
    ) -> None:
        drafts = [MessageDraft(sender='a@example.com', subject='s', body=['b'])]
        selection = Mailbox(mailbox_writer.write(drafts)).select()
        target = mailbox_writer.index_path().with_suffix('.parquet')
        selection.to_parquet(target, compression=compression)  # ty: ignore[invalid-argument-type]
        assert pq.read_table(target).to_pylist()[0]['subject'] == 's'

    def test_an_unknown_compression_is_rejected(
        self, mailbox_writer: MailboxWriter
    ) -> None:
        drafts = [MessageDraft(sender='a@example.com', subject='s', body=['b'])]
        selection = Mailbox(mailbox_writer.write(drafts)).select()
        with pytest.raises(ValueError, match='unknown compression'):
            selection.to_parquet('x.parquet', compression='lz4')  # ty: ignore[invalid-argument-type]

    def test_a_missing_directory_raises_file_not_found(
        self, mailbox_writer: MailboxWriter
    ) -> None:
        drafts = [MessageDraft(sender='a@example.com', subject='s', body=['b'])]
        target = Path(mailbox_writer.directory, 'absent', 'out.parquet')
        with pytest.raises(FileNotFoundError):
            Mailbox(mailbox_writer.write(drafts)).select().to_parquet(target)

    @pytest.mark.regression
    @given(contents=hostile_mailboxes)
    @example(contents=b'From a\nSubject: s\nReceived:\n\t')
    @example(contents=b'From a\nContent-Type: message/rfc822\n\nno headers here\n')
    def test_every_column_extracts_from_hostile_input(
        self, mailbox_writer: MailboxWriter, contents: bytes
    ) -> None:
        mailbox = Mailbox(mailbox_writer.write_raw(contents))
        assert pa.table(mailbox.select(self.ALL_COLUMNS)).num_rows == len(mailbox)


class TestParquetOverwrite:
    @pytest.fixture
    def selection(self, mailbox_writer: MailboxWriter) -> Selection:
        drafts = [MessageDraft(sender='a@example.com', subject='s', body=['b'])]
        return Mailbox(mailbox_writer.write(drafts)).select(['subject'])

    def test_an_existing_file_is_refused_and_left_unchanged(
        self, selection: Selection, tmp_path: Path
    ) -> None:
        target = tmp_path / 'out.parquet'
        target.write_bytes(b'precious')
        with pytest.raises(FileExistsError) as refused:
            selection.to_parquet(target)
        assert str(target) in str(refused.value.filename)
        assert target.read_bytes() == b'precious'

    def test_overwrite_replaces_an_existing_file(
        self, selection: Selection, tmp_path: Path
    ) -> None:
        target = tmp_path / 'out.parquet'
        target.write_bytes(b'stale')
        assert selection.to_parquet(target, overwrite=True) == 1
        assert pq.read_table(target).to_pylist() == [{'subject': 's'}]

    def test_overwrite_refuses_an_unrelated_directory_and_leaves_it_unchanged(
        self, selection: Selection, tmp_path: Path
    ) -> None:
        target = tmp_path / 'out.parquet'
        target.mkdir()
        (target / 'keep.txt').write_bytes(b'precious')
        with pytest.raises(FileExistsError) as refused:
            selection.to_parquet(target, overwrite=True)
        assert str(target) in str(refused.value.filename)
        assert [entry.name for entry in target.iterdir()] == ['keep.txt']
        assert (target / 'keep.txt').read_bytes() == b'precious'


@pytest.mark.skipif(
    bool(sysconfig.get_config_var('Py_GIL_DISABLED')),
    reason='free-threaded build: the counter runs whether or not to_parquet detaches',
)
class TestGilRelease:
    # Without py.detach the counter lands exactly 1 tick inside the export, whatever
    # the core count or fixture size. With it, 100k messages gave at least 10 ticks on
    # 12 cores and 15 to 17 on 2 to 4 cores, where 20k messages gave as few as 4.
    MESSAGES = 100_000
    MIN_TICKS = 5

    @pytest.fixture
    def selection(self, mailbox_writer: MailboxWriter) -> Selection:
        drafts = [
            MessageDraft(sender='a@example.com', subject=f'n{n}', body=['b'] * 20)
            for n in range(self.MESSAGES)
        ]
        return Mailbox(mailbox_writer.write(drafts)).select(['raw', 'text'])

    def test_other_threads_run_while_to_parquet_exports(
        self, selection: Selection, tmp_path: Path
    ) -> None:
        stop, ticks = threading.Event(), []

        def count() -> None:
            while not stop.is_set():
                ticks.append(time.perf_counter())
                time.sleep(0.001)

        counter = threading.Thread(target=count)
        counter.start()
        while not ticks:
            time.sleep(0.001)
        started = time.perf_counter()
        try:
            selection.to_parquet(tmp_path / 'out.parquet')
        finally:
            finished = time.perf_counter()
            stop.set()
            counter.join()
        during = [tick for tick in ticks if started < tick < finished]
        assert len(during) >= self.MIN_TICKS, (
            'the counter thread advanced while the export ran'
        )
