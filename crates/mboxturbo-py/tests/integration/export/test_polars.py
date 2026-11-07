"""polars reads a selection through the Arrow C stream; skipped where it has no wheel."""

import pytest

from mboxturbo import Mailbox
from mboxturbo.tests.drafts import MailboxWriter, MessageDraft

pl = pytest.importorskip('polars')
pytestmark = pytest.mark.integration


class TestPolars:
    SAMPLE = (MessageDraft(sender='a@example.com', subject='s', body=['b']),)

    @pytest.fixture
    def mailbox(self, mailbox_writer: MailboxWriter) -> Mailbox:
        return Mailbox(mailbox_writer.write(self.SAMPLE))

    def test_polars_reads_a_selection_as_a_data_frame(self, mailbox: Mailbox) -> None:
        frame = pl.DataFrame(mailbox.select(['position', 'subject']))
        assert frame.to_dicts() == [{'position': 0, 'subject': 's'}]
