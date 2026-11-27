"""Another Python thread runs while pyarrow and polars consume a selection's stream."""

import threading
import time
from collections.abc import Callable

import pyarrow as pa
import pytest

from mboxturbo import Mailbox
from mboxturbo.tests.drafts import MailboxWriter, MessageDraft

pl = pytest.importorskip('polars')
pytestmark = pytest.mark.integration

MESSAGES = 30000
COLUMNS = (
    'position',
    'from',
    'subject',
    'date',
    'message_id',
    'text',
    'attachment_sha256',
)
MIN_SHARE = 0.2


def count_while(work: Callable[[], object]) -> tuple[int, float]:
    """Iterations a pure Python thread makes while ``work`` runs, and the wall time."""
    stop, counts = threading.Event(), [0]

    def count() -> None:
        iterations = 0
        while not stop.is_set():
            time.perf_counter()
            iterations += 1
        counts[0] = iterations

    counter = threading.Thread(target=count)
    counter.start()
    started = time.perf_counter()
    try:
        work()
    finally:
        elapsed = time.perf_counter() - started
        stop.set()
        counter.join()
    return counts[0], elapsed


class TestGilRelease:
    @pytest.fixture
    def mailbox(self, mailbox_writer: MailboxWriter) -> Mailbox:
        drafts = [
            MessageDraft(
                sender=f'a{index}@example.com',
                subject=f'subject {index}',
                body=[f'line {line} of message {index}' for line in range(100)],
            )
            for index in range(MESSAGES)
        ]
        return Mailbox(mailbox_writer.write(drafts))

    @pytest.mark.parametrize(
        'consume',
        [pa.table, pl.DataFrame],
        ids=['pyarrow', 'polars'],
    )
    def test_a_python_thread_runs_while_a_consumer_reads_the_stream(
        self, mailbox: Mailbox, consume: Callable[[object], object]
    ) -> None:
        def read() -> object:
            return consume(mailbox.select(COLUMNS, batch_size=64))

        read()
        busy, elapsed = count_while(read)
        idle, _ = count_while(lambda: time.sleep(elapsed))
        assert busy > MIN_SHARE * idle, f'busy={busy} idle={idle} over {elapsed:.3f}s'
