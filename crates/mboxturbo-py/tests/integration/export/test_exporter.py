"""Python exporters run under the Rust export driver through ``Selection.export``."""

import os
import signal
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from mboxturbo import (
    ArrowBatchLike,
    ArrowSchemaLike,
    ByteSink,
    Cancelled,
    CancelToken,
    Mailbox,
    Selection,
)
from mboxturbo.tests.drafts import MailboxWriter, MessageDraft

pytestmark = pytest.mark.integration

MESSAGES = 20
BATCH_SIZE = 5
BATCHES = MESSAGES // BATCH_SIZE
SLOW_BATCH_SECONDS = 0.05
JOIN_SECONDS = 10
STAGES = ('begin', 'write_batch', 'finish')


class ExporterError(Exception):
    pass


class CsvExporter:
    def __init__(self, *, fail_in: str | None = None, delay: float = 0.0) -> None:
        self.calls: list[str] = []
        self.fail_in = fail_in
        self.delay = delay
        self.seen_target: list[bool] = []
        self.failure = ExporterError('boom')

    def begin(self, schema: ArrowSchemaLike, out: ByteSink, /) -> None:
        self.step('begin')
        out.write(','.join(pa.schema(schema).names).encode() + b'\n')

    def write_batch(self, batch: ArrowBatchLike, out: ByteSink, /) -> None:
        self.step('write_batch')
        time.sleep(self.delay)
        for row in pa.record_batch(batch).to_pylist():
            out.write(','.join(map(str, row.values())).encode() + b'\n')

    def finish(self, out: ByteSink, /) -> None:
        self.step('finish')
        out.write(bytearray(b'# end\n'))

    def step(self, name: str) -> None:
        self.calls.append(name)
        if name == self.fail_in:
            raise self.failure


class FilePerBatchExporter:
    kind = 'directory'

    def __init__(self, *, fail_in: str | None = None) -> None:
        self.calls: list[str] = []
        self.outs: list[Path] = []
        self.fail_in = fail_in
        self.failure = ExporterError('boom')

    def begin(self, schema: ArrowSchemaLike, out: Path, /) -> None:
        self.step('begin', out)
        assert pa.schema(schema).names == ['position', 'subject']

    def write_batch(self, batch: ArrowBatchLike, out: Path, /) -> None:
        self.step('write_batch', out)
        pq.write_table(
            pa.Table.from_batches([pa.record_batch(batch)]),
            out / f'batch-{self.calls.count("write_batch"):03}.parquet',
        )

    def finish(self, out: Path, /) -> None:
        self.step('finish', out)
        (out / 'DONE').write_text('done', encoding='utf-8')

    def step(self, name: str, out: Path) -> None:
        self.calls.append(name)
        self.outs.append(out)
        if name == self.fail_in:
            raise self.failure


@pytest.fixture
def selection(mailbox_writer: MailboxWriter) -> Selection:
    drafts = [
        MessageDraft(sender='a@example.com', subject=f's{index}', body=['b'])
        for index in range(MESSAGES)
    ]
    return Mailbox(mailbox_writer.write(drafts)).select(
        ['position', 'subject'], batch_size=BATCH_SIZE
    )


@pytest.fixture
def target(tmp_path: Path) -> Path:
    return tmp_path / 'out'


def csv_text() -> str:
    rows = [f'{index},s{index}\n' for index in range(MESSAGES)]
    return 'position,subject\n' + ''.join(rows) + '# end\n'


class TestFileExporter:
    def test_the_exporter_is_called_in_order_and_writes_the_file(
        self, selection: Selection, target: Path
    ) -> None:
        exporter = CsvExporter()
        assert selection.export(exporter, target) == MESSAGES
        assert exporter.calls == ['begin', *['write_batch'] * BATCHES, 'finish']
        assert target.read_text(encoding='utf-8') == csv_text()
        assert sorted(path.name for path in target.parent.iterdir()) == [target.name]

    def test_nothing_lands_at_the_target_before_finish(
        self, selection: Selection, target: Path
    ) -> None:
        class Watcher(CsvExporter):
            def finish(self, out: ByteSink, /) -> None:
                self.seen_target.append(target.exists())
                super().finish(out)

        exporter = Watcher()
        selection.export(exporter, target)
        assert exporter.seen_target == [False]
        assert target.exists()

    def test_out_write_returns_the_length_and_rejects_text(
        self, selection: Selection, target: Path
    ) -> None:
        lengths: list[int] = []

        class Probe(CsvExporter):
            def begin(self, _schema: ArrowSchemaLike, out: ByteSink, /) -> None:
                lengths.append(out.write(b'abc'))
                with pytest.raises(TypeError):
                    out.write('text')  # ty: ignore[invalid-argument-type]

        selection.export(Probe(), target)
        assert lengths == [3]

    def test_polars_reads_the_batches(self, selection: Selection, target: Path) -> None:
        pl = pytest.importorskip('polars')
        frames: list[object] = []

        class Reader(CsvExporter):
            def write_batch(self, batch: ArrowBatchLike, out: ByteSink, /) -> None:
                frames.append(pl.DataFrame(pa.record_batch(batch)))
                super().write_batch(batch, out)

        selection.export(Reader(), target)
        combined = pl.concat(frames)
        assert combined['position'].to_list() == list(range(MESSAGES))
        assert combined['subject'][3] == 's3'

    def test_an_unknown_kind_is_a_value_error(
        self, selection: Selection, target: Path
    ) -> None:
        exporter = CsvExporter()
        exporter.kind = 'stream'  # ty: ignore[unresolved-attribute]
        with pytest.raises(ValueError, match='kind'):
            selection.export(exporter, target)
        assert exporter.calls == []


class TestDirectoryExporter:
    def test_each_batch_lands_as_a_file_in_the_staging_directory(
        self, selection: Selection, target: Path
    ) -> None:
        exporter = FilePerBatchExporter()
        assert selection.export(exporter, target) == MESSAGES
        assert exporter.calls == ['begin', *['write_batch'] * BATCHES, 'finish']
        assert exporter.outs[0] != target
        assert len(set(exporter.outs)) == 1
        assert all(isinstance(out, Path) for out in exporter.outs)
        names = sorted(path.name for path in target.iterdir())
        assert names == ['DONE', *(f'batch-{n:03}.parquet' for n in range(1, 5))]
        table = pa.concat_tables(
            pq.read_table(path) for path in sorted(target.glob('*.parquet'))
        )
        assert table['position'].to_pylist() == list(range(MESSAGES))
        assert sorted(path.name for path in target.parent.iterdir()) == [target.name]


def exporter_of(kind: str, fail_in: str | None) -> CsvExporter | FilePerBatchExporter:
    if kind == 'file':
        return CsvExporter(fail_in=fail_in)
    return FilePerBatchExporter(fail_in=fail_in)


@dataclass
class Run:
    selection: Selection
    target: Path
    exporter: CsvExporter | FilePerBatchExporter

    def export(self, *, overwrite: bool = False) -> int:
        return self.selection.export(self.exporter, self.target, overwrite=overwrite)


class TestFailures:
    @pytest.fixture(
        params=[(kind, stage) for kind in ('file', 'directory') for stage in STAGES],
        ids=lambda case: f'{case[0]}-{case[1]}',
    )
    def run(
        self,
        request: pytest.FixtureRequest,
        selection: Selection,
        target: Path,
    ) -> Run:
        kind, stage = request.param
        return Run(selection, target, exporter_of(kind, stage))

    def test_the_original_exception_propagates_and_nothing_is_left(
        self, run: Run
    ) -> None:
        with pytest.raises(ExporterError) as raised:
            run.export()
        assert raised.value is run.exporter.failure
        assert list(run.target.parent.iterdir()) == []

    def test_a_failure_leaves_an_overwritten_target_byte_identical(
        self, run: Run
    ) -> None:
        kind = 'file' if isinstance(run.exporter, CsvExporter) else 'directory'
        good = Run(run.selection, run.target, exporter_of(kind, None))
        good.export()
        if kind == 'directory':
            (run.target / 'manifest.jsonl').write_bytes(b'')
        before = sorted((path.name, path.read_bytes()) for path in walk(run.target))
        with pytest.raises(ExporterError):
            run.export(overwrite=True)
        after = sorted((path.name, path.read_bytes()) for path in walk(run.target))
        assert after == before
        assert sorted(path.name for path in run.target.parent.iterdir()) == [
            run.target.name
        ]


def walk(path: Path) -> list[Path]:
    return [path] if path.is_file() else sorted(path.iterdir())


class TestOverwrite:
    def test_an_existing_target_is_refused_before_begin(
        self, selection: Selection, target: Path
    ) -> None:
        target.write_text('keep', encoding='utf-8')
        exporter = CsvExporter()
        with pytest.raises(FileExistsError):
            selection.export(exporter, target)
        assert exporter.calls == []
        assert target.read_text(encoding='utf-8') == 'keep'

    def test_overwrite_replaces_the_target(
        self, selection: Selection, target: Path
    ) -> None:
        target.write_text('old', encoding='utf-8')
        selection.export(CsvExporter(), target, overwrite=True)
        assert target.read_text(encoding='utf-8') == csv_text()


class TestProgressAndCancel:
    def test_progress_reports_each_batch_up_to_the_total(
        self, selection: Selection, target: Path
    ) -> None:
        calls: list[tuple[int, int]] = []
        selection.export(
            CsvExporter(),
            target,
            progress=lambda done, total: calls.append((done, total)),
        )
        assert [done for done, _ in calls] == [5, 10, 15, 20]
        assert {total for _, total in calls} == {MESSAGES}

    def test_a_cancelled_token_leaves_nothing(
        self, selection: Selection, target: Path
    ) -> None:
        token = CancelToken()
        token.cancel()
        with pytest.raises(Cancelled):
            selection.export(CsvExporter(), target, cancel=token)
        assert list(target.parent.iterdir()) == []

    def test_a_raising_callback_cancels_with_its_exception_as_the_cause(
        self, selection: Selection, target: Path
    ) -> None:
        failure = ExporterError('callback')

        def fail(*_progress: int) -> None:
            raise failure

        with pytest.raises(Cancelled) as raised:
            selection.export(CsvExporter(), target, progress=fail)
        assert raised.value.__cause__ is failure
        assert not target.exists()

    def test_ctrl_c_cancels_with_the_keyboard_interrupt_as_the_cause(
        self, selection: Selection, target: Path
    ) -> None:
        started = threading.Event()

        class Slow(CsvExporter):
            def write_batch(self, batch: ArrowBatchLike, out: ByteSink, /) -> None:
                started.set()
                super().write_batch(batch, out)

        sender = threading.Thread(
            target=lambda: (
                started.wait(JOIN_SECONDS),
                os.kill(os.getpid(), signal.SIGINT),
            )
        )
        sender.start()
        exporter = Slow(delay=SLOW_BATCH_SECONDS)
        with pytest.raises(Cancelled) as raised:
            selection.export(exporter, target)
        sender.join(JOIN_SECONDS)
        assert isinstance(raised.value.__cause__, KeyboardInterrupt)
        assert exporter.calls.count('write_batch') < BATCHES
        assert list(target.parent.iterdir()) == []
