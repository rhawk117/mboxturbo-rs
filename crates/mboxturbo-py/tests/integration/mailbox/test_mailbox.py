"""Indexing, access, iteration, batching, caching and lifecycle of Mailbox."""

import os
from collections import Counter
from collections.abc import Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from itertools import chain
from pathlib import Path

import pytest
from hypothesis import example, given
from hypothesis import strategies as st

from mboxturbo import CorruptIndexError, Mailbox, Message
from mboxturbo.tests.drafts import (
    MailboxWriter,
    MessageDraft,
    mailbox_drafts,
    message_drafts,
)

pytestmark = pytest.mark.integration


def raw_of(message: Message) -> bytes:
    return message.raw


def render_all(drafts: Sequence[MessageDraft]) -> list[bytes]:
    return [draft.render() for draft in drafts]


class TestIndexing:
    @given(drafts=mailbox_drafts)
    def test_every_message_round_trips_byte_exact(
        self, mailbox_writer: MailboxWriter, drafts: Sequence[MessageDraft]
    ) -> None:
        mailbox = Mailbox(mailbox_writer.write(drafts))
        assert len(mailbox) == len(drafts)
        assert list(map(raw_of, mailbox)) == render_all(drafts)

    @given(drafts=st.lists(message_drafts, min_size=1, max_size=12), data=st.data())
    def test_positions_index_like_a_list_including_negative_ones(
        self,
        mailbox_writer: MailboxWriter,
        drafts: Sequence[MessageDraft],
        data: st.DataObject,
    ) -> None:
        position = data.draw(st.integers(-len(drafts), len(drafts) - 1))
        mailbox = Mailbox(mailbox_writer.write(drafts))
        assert mailbox[position].raw == render_all(drafts)[position]

    @pytest.mark.regression
    @given(drafts=mailbox_drafts, overshoot=st.integers(0, 2**80))
    @example(drafts=[], overshoot=2**70)
    def test_positions_past_either_end_raise_index_error(
        self,
        mailbox_writer: MailboxWriter,
        drafts: Sequence[MessageDraft],
        overshoot: int,
    ) -> None:
        mailbox = Mailbox(mailbox_writer.write(drafts))
        with pytest.raises(IndexError):
            mailbox[len(drafts) + overshoot]
        with pytest.raises(IndexError):
            mailbox[-len(drafts) - 1 - overshoot]

    @given(drafts=mailbox_drafts, data=st.data())
    def test_slices_select_exactly_what_list_slicing_selects(
        self,
        mailbox_writer: MailboxWriter,
        drafts: Sequence[MessageDraft],
        data: st.DataObject,
    ) -> None:
        selection = data.draw(st.slices(len(drafts)))
        mailbox = Mailbox(mailbox_writer.write(drafts))
        assert list(map(raw_of, mailbox[selection])) == render_all(drafts)[selection]

    @given(drafts=mailbox_drafts, key=st.text() | st.floats() | st.none())
    def test_keys_that_are_not_integers_or_slices_raise_type_error(
        self,
        mailbox_writer: MailboxWriter,
        drafts: Sequence[MessageDraft],
        key: str | float | None,
    ) -> None:
        mailbox = Mailbox(mailbox_writer.write(drafts))
        with pytest.raises(TypeError):
            mailbox[key]  # ty: ignore[invalid-argument-type]


class TestBatches:
    SAMPLE = (
        MessageDraft(sender='a@example.com', subject='one', body=['x']),
        MessageDraft(sender='b@example.com', subject='two', body=['y']),
    )

    @pytest.fixture
    def mailbox(self, mailbox_writer: MailboxWriter) -> Mailbox:
        return Mailbox(mailbox_writer.write(self.SAMPLE))

    @given(drafts=mailbox_drafts, size=st.integers(1, 15))
    def test_batches_concatenate_to_the_whole_mailbox_in_order(
        self,
        mailbox_writer: MailboxWriter,
        drafts: Sequence[MessageDraft],
        size: int,
    ) -> None:
        batches = list(Mailbox(mailbox_writer.write(drafts)).batches(size))
        assert all(len(batch) <= size for batch in batches)
        assert list(map(raw_of, chain.from_iterable(batches))) == render_all(drafts)

    def test_batches_arrive_already_parsed(self, mailbox: Mailbox) -> None:
        subjects = [message.subject for message in next(mailbox.batches(10))]
        assert subjects == ['one', 'two']

    def test_a_batch_size_of_zero_is_rejected(self, mailbox: Mailbox) -> None:
        with pytest.raises(ValueError, match='batch size must be positive'):
            mailbox.batches(0)


class TestSharedIteration:
    WORKERS = 4
    MESSAGES = 2_000

    @pytest.fixture
    def mailbox(self, mailbox_writer: MailboxWriter) -> Mailbox:
        drafts = [
            MessageDraft(sender='s@example.com', subject=f'n{number}', body=['b'])
            for number in range(self.MESSAGES)
        ]
        return Mailbox(mailbox_writer.write(drafts))

    def drain_concurrently(self, iterator: Iterator[Message]) -> Counter[str | None]:
        with ThreadPoolExecutor(max_workers=self.WORKERS) as pool:
            drained = [pool.submit(list, iterator) for _ in range(self.WORKERS)]
        return Counter(
            message.subject
            for message in chain.from_iterable(future.result() for future in drained)
        )

    def test_threads_sharing_one_iterator_each_claim_distinct_messages(
        self, mailbox: Mailbox
    ) -> None:
        claimed = self.drain_concurrently(iter(mailbox))
        assert claimed == Counter(f'n{number}' for number in range(self.MESSAGES))

    def test_threads_sharing_one_batch_iterator_each_claim_distinct_batches(
        self, mailbox: Mailbox
    ) -> None:
        batches = mailbox.batches(37)
        with ThreadPoolExecutor(max_workers=self.WORKERS) as pool:
            drained = [pool.submit(list, batches) for _ in range(self.WORKERS)]
        messages = chain.from_iterable(chain.from_iterable(f.result() for f in drained))
        claimed = Counter(message.subject for message in messages)
        assert claimed == Counter(f'n{number}' for number in range(self.MESSAGES))


class TestLifecycle:
    SAMPLE = (MessageDraft(sender='a@example.com', subject='kept', body=['x']),)

    @pytest.fixture
    def mailbox(self, mailbox_writer: MailboxWriter) -> Mailbox:
        return Mailbox(mailbox_writer.write(self.SAMPLE))

    def test_a_closed_mailbox_refuses_access(self, mailbox: Mailbox) -> None:
        mailbox.close()
        with pytest.raises(ValueError, match='closed mailbox'):
            len(mailbox)

    def test_messages_and_iterators_taken_before_close_keep_working(
        self, mailbox: Mailbox
    ) -> None:
        message, iterator = mailbox[0], iter(mailbox)
        mailbox.close()
        assert message.subject == 'kept'
        assert next(iterator).subject == 'kept'

    def test_the_context_manager_closes_on_exit(self, mailbox: Mailbox) -> None:
        with mailbox as opened:
            assert len(opened) == 1
        with pytest.raises(ValueError, match='closed mailbox'):
            iter(mailbox)


@dataclass(slots=True, kw_only=True, frozen=True)
class CachedMailbox:
    mailbox: Path
    index: Path


class TestIndexCache:
    SAMPLE = (
        MessageDraft(sender='a@example.com', subject='one', body=['x']),
        MessageDraft(sender='b@example.com', subject='two', body=['y']),
    )

    @pytest.fixture
    def paths(self, mailbox_writer: MailboxWriter) -> CachedMailbox:
        return CachedMailbox(
            mailbox=mailbox_writer.write(self.SAMPLE),
            index=mailbox_writer.index_path(),
        )

    def test_a_missing_cache_is_written_and_then_reused(
        self, paths: CachedMailbox
    ) -> None:
        Mailbox(paths.mailbox, index=paths.index)
        written = paths.index.stat().st_mtime_ns
        assert len(Mailbox(paths.mailbox, index=paths.index)) == len(self.SAMPLE)
        assert paths.index.stat().st_mtime_ns == written

    def test_a_stale_cache_is_rebuilt_and_rewritten(self, paths: CachedMailbox) -> None:
        Mailbox(paths.mailbox, index=paths.index)
        stale = paths.index.read_bytes()
        with paths.mailbox.open('ab') as appended:
            appended.write(self.SAMPLE[0].render())
        assert len(Mailbox(paths.mailbox, index=paths.index)) == len(self.SAMPLE) + 1
        assert paths.index.read_bytes() != stale

    def test_a_corrupt_cache_raises_and_is_left_for_inspection(
        self, paths: CachedMailbox
    ) -> None:
        Mailbox(paths.mailbox, index=paths.index)
        damaged = bytearray(paths.index.read_bytes())
        damaged[60] ^= 0xFF
        paths.index.write_bytes(damaged)
        with pytest.raises(CorruptIndexError, match='checksum mismatch'):
            Mailbox(paths.mailbox, index=paths.index)
        assert paths.index.read_bytes() == damaged

    def test_a_saved_index_is_accepted_as_a_cache(self, paths: CachedMailbox) -> None:
        Mailbox(paths.mailbox).save_index(paths.index)
        saved = paths.index.stat().st_mtime_ns
        assert len(Mailbox(paths.mailbox, index=paths.index)) == len(self.SAMPLE)
        assert paths.index.stat().st_mtime_ns == saved


class TestOpenErrors:
    def test_a_missing_mailbox_raises_file_not_found_naming_it(
        self, mailbox_writer: MailboxWriter
    ) -> None:
        missing = mailbox_writer.directory.joinpath('absent.mbox')
        with pytest.raises(FileNotFoundError) as raised:
            Mailbox(missing)
        assert os.fspath(raised.value.filename) == os.fspath(missing)
