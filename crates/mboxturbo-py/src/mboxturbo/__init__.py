"""Random access, parallel indexing and Rust-parsed messages for mbox files."""

from pathlib import Path
from typing import Protocol

from mboxturbo._bin import MboxTurboBinNotFoundError, find_mboxturbo_bin
from mboxturbo._core import (
    Address,
    Attachment,
    Cancelled,
    CancelToken,
    CorruptIndexError,
    HeaderBuilder,
    Mailbox,
    MboxTurboError,
    Message,
    Predicate,
    Selection,
    StaleIndexError,
    Trust,
    VerdictBuilder,
    column_names,
    header,
    verdict,
)


class ArrowSchemaLike(Protocol):
    """The schema an exporter receives; ``pyarrow.schema`` imports it."""

    def __arrow_c_schema__(self) -> object: ...  # noqa: PLW3201


class ArrowBatchLike(Protocol):
    """A batch an exporter receives; ``pyarrow.record_batch`` imports it."""

    def __arrow_c_array__(  # noqa: PLW3201
        self, requested_schema: object | None = None
    ) -> tuple[object, object]: ...


class ByteSink(Protocol):
    """The ``out`` of a file exporter; its bytes join the staged file."""

    def write(self, data: bytes | bytearray, /) -> int: ...


class Exporter[Out: (ByteSink, Path)](Protocol):
    """Writes the batches of ``Selection.export``.

    ``out`` is a ``ByteSink`` for the default ``kind = 'file'`` and the staging
    directory for ``kind = 'directory'``; give the exporter a ``kind`` attribute to
    choose. ``begin`` runs once, ``write_batch`` once per batch and ``finish`` once
    after the last batch; nothing reaches the target unless ``finish`` returns.
    """

    def begin(self, schema: ArrowSchemaLike, out: Out, /) -> None:
        """Called once before the first batch with the Arrow schema of every batch."""

    def write_batch(self, batch: ArrowBatchLike, out: Out, /) -> None:
        """Called once per batch, in row order, to write it to ``out``."""

    def finish(self, out: Out, /) -> None:
        """Called once after the last batch; the target appears only if this returns."""


SOC_COLUMNS: tuple[str, ...] = (
    *column_names(opt_in=False),
    *(name for name in column_names(opt_in=True) if name != 'raw'),
)
"""The default columns plus every structured and verdict column."""

__all__ = [
    'SOC_COLUMNS',
    'Address',
    'ArrowBatchLike',
    'ArrowSchemaLike',
    'Attachment',
    'ByteSink',
    'CancelToken',
    'Cancelled',
    'CorruptIndexError',
    'Exporter',
    'HeaderBuilder',
    'Mailbox',
    'MboxTurboBinNotFoundError',
    'MboxTurboError',
    'Message',
    'Predicate',
    'Selection',
    'StaleIndexError',
    'Trust',
    'VerdictBuilder',
    'find_mboxturbo_bin',
    'header',
    'verdict',
]
