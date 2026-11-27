"""Random access, parallel indexing and Rust-parsed messages for mbox files."""

from mboxturbo._core import (
    Address,
    Attachment,
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

__all__ = [
    'Address',
    'Attachment',
    'CorruptIndexError',
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
