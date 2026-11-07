"""Random access, parallel indexing and Rust-parsed messages for mbox files."""

from mboxturbo._core import (
    Address,
    Attachment,
    CorruptIndexError,
    Mailbox,
    MboxTurboError,
    Message,
    Selection,
    StaleIndexError,
)

__all__ = [
    'Address',
    'Attachment',
    'CorruptIndexError',
    'Mailbox',
    'MboxTurboError',
    'Message',
    'Selection',
    'StaleIndexError',
]
