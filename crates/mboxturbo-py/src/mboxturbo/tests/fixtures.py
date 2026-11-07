"""Pytest plugin providing a per-class factory for mailbox files."""

import pytest

from mboxturbo.tests.drafts import MailboxWriter


@pytest.fixture(scope='class')
def mailbox_writer(tmp_path_factory: pytest.TempPathFactory) -> MailboxWriter:
    return MailboxWriter(directory=tmp_path_factory.mktemp('mailboxes'))
