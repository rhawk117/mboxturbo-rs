"""Random access, parallel indexing and Rust-parsed messages for mbox files."""

from pathlib import Path
from typing import Protocol

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

    def begin(self, schema: ArrowSchemaLike, out: Out, /) -> None: ...

    def write_batch(self, batch: ArrowBatchLike, out: Out, /) -> None: ...

    def finish(self, out: Out, /) -> None: ...


__all__ = [
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
    'MboxTurboError',
    'Message',
    'Predicate',
    'Selection',
    'StaleIndexError',
    'Trust',
    'VerdictBuilder',
    'header',
    'verdict',
]
