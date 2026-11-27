"""Progress, cancellation and Ctrl-C for Parquet exports."""

import os
import signal
import threading
import time
from pathlib import Path

import pytest

from mboxturbo import Cancelled, CancelToken, Mailbox, MboxTurboError, Selection
from mboxturbo.tests.drafts import MailboxWriter, MessageDraft

pytestmark = pytest.mark.integration

MESSAGES = 60
SLOW_CALLBACK_SECONDS = 0.02
JOIN_SECONDS = 10


class CallbackError(Exception):
    pass


class Recorder:
    def __init__(self, *, delay: float = 0.0) -> None:
        self.calls: list[tuple[int, int]] = []
        self.first = threading.Event()
        self.delay = delay

    def __call__(self, done: int, total: int) -> None:
        self.calls.append((done, total))
        self.first.set()
        time.sleep(self.delay)


class TestProgress:
    @pytest.fixture
    def selection(self, mailbox_writer: MailboxWriter) -> Selection:
        drafts = [
            MessageDraft(sender='a@example.com', subject=f's{index}', body=['b'])
            for index in range(MESSAGES)
        ]
        return Mailbox(mailbox_writer.write(drafts)).select(
            ['position', 'subject'], batch_size=2
        )

    @pytest.fixture
    def target(self, tmp_path: Path) -> Path:
        return tmp_path / 'out.parquet'

    def test_progress_reports_each_batch_up_to_the_total(
        self, selection: Selection, target: Path
    ) -> None:
        recorder = Recorder()
        written = selection.to_parquet(target, progress=recorder)
        dones = [done for done, _ in recorder.calls]
        assert written == MESSAGES
        assert len(dones) > 1
        assert dones == sorted(dones)
        assert recorder.calls[-1] == (MESSAGES, MESSAGES)
        assert {total for _, total in recorder.calls} == {MESSAGES}

    def test_a_cancelled_token_stops_the_export_and_leaves_no_file(
        self, selection: Selection, target: Path
    ) -> None:
        token = CancelToken()
        assert not token.is_cancelled
        token.cancel()
        assert token.is_cancelled
        with pytest.raises(Cancelled) as raised:
            selection.to_parquet(target, cancel=token)
        assert raised.value.__cause__ is None
        assert isinstance(raised.value, MboxTurboError)
        assert not target.exists()

    def test_a_token_cancelled_from_another_thread_stops_the_export(
        self, selection: Selection, target: Path
    ) -> None:
        token = CancelToken()
        recorder = Recorder(delay=SLOW_CALLBACK_SECONDS)
        canceller = threading.Thread(
            target=lambda: (recorder.first.wait(JOIN_SECONDS), token.cancel())
        )
        canceller.start()
        with pytest.raises(Cancelled):
            selection.to_parquet(target, progress=recorder, cancel=token)
        canceller.join(JOIN_SECONDS)
        assert recorder.calls[-1][0] < MESSAGES
        assert not target.exists()

    def test_a_raising_callback_cancels_with_its_exception_as_the_cause(
        self, selection: Selection, target: Path
    ) -> None:
        failure = CallbackError('boom')

        def fail(*_progress: int) -> None:
            raise failure

        with pytest.raises(Cancelled) as raised:
            selection.to_parquet(target, progress=fail)
        assert raised.value.__cause__ is failure
        assert raised.value.__cause__.__traceback__ is not None
        assert not target.exists()

    def test_ctrl_c_cancels_with_the_keyboard_interrupt_as_the_cause(
        self, selection: Selection, target: Path
    ) -> None:
        recorder = Recorder(delay=SLOW_CALLBACK_SECONDS)
        sender = threading.Thread(
            target=lambda: (
                recorder.first.wait(JOIN_SECONDS),
                os.kill(os.getpid(), signal.SIGINT),
            )
        )
        sender.start()
        with pytest.raises(Cancelled) as raised:
            selection.to_parquet(target, progress=recorder)
        sender.join(JOIN_SECONDS)
        assert isinstance(raised.value.__cause__, KeyboardInterrupt)
        assert recorder.calls[-1][0] < MESSAGES
        assert not target.exists()

    @pytest.mark.parametrize('stop', ['token', 'callback'])
    def test_a_stop_leaves_an_existing_target_byte_identical(
        self, selection: Selection, target: Path, stop: str
    ) -> None:
        selection.to_parquet(target)
        before = target.read_bytes()
        token = CancelToken()

        def fail(*_progress: int) -> None:
            raise CallbackError

        if stop == 'token':
            token.cancel()
        with pytest.raises(Cancelled):
            selection.to_parquet(
                target,
                overwrite=True,
                cancel=token,
                progress=fail if stop == 'callback' else None,
            )
        assert target.read_bytes() == before
        assert sorted(path.name for path in target.parent.iterdir()) == [target.name]
