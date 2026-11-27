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
MIN_SHARE = 0.3
READS = 12
FLOATS = 3_000_000


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


def share(work: Callable[[], object]) -> tuple[float, float]:
    """A Python thread's iterations during ``work`` over an idle run's, and the time."""
    busy, elapsed = count_while(work)
    idle, _ = count_while(lambda: time.sleep(elapsed))
    return busy / idle, elapsed


class TestGilRelease:
    def test_a_call_that_holds_the_gil_starves_the_python_thread(self) -> None:
        values = [float(index * 7919 % 1_000_003) for index in range(FLOATS)]
        measured, elapsed = share(lambda: sorted(values))
        assert measured < MIN_SHARE, f'share={measured:.3f} over {elapsed:.3f}s'

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
        def read() -> None:
            for _ in range(READS):
                consume(mailbox.select(COLUMNS, batch_size=64))

        read()
        measured, elapsed = share(read)
        assert measured > MIN_SHARE, f'share={measured:.3f} over {elapsed:.3f}s'
