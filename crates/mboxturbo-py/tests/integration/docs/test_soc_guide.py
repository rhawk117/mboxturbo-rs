"""The SOC guide's examples run, its columns exist, and the public API is documented."""

import re
from pathlib import Path

import pytest

import mboxturbo
from mboxturbo import Mailbox
from mboxturbo.tests.drafts import MailboxWriter, MessageDraft

pytestmark = pytest.mark.integration

REPOSITORY = Path(__file__).resolve().parents[5]
GUIDE = REPOSITORY / 'docs' / 'soc-guide.md'
PYTHON_BLOCK = re.compile(r'^```python\n(.*?)^```$', re.MULTILINE | re.DOTALL)
GUIDE_COLUMNS = (
    'auth_results',
    'arc_sets',
    'dkim_signatures',
    'received_hops',
    'received_spf_parsed',
    'microsoft_antispam',
    'verdict_dmarc',
    'verdict_spf',
    'verdict_dkim',
    'verdict_compauth',
)


def opt_in_names() -> set[str]:
    return set(mboxturbo.column_names(opt_in=True))


class TestGuide:
    def test_every_python_block_runs_in_order(self) -> None:
        blocks = PYTHON_BLOCK.findall(GUIDE.read_text())
        assert blocks
        namespace: dict[str, object] = {'__name__': 'soc_guide'}
        for block in blocks:
            exec(compile(block, str(GUIDE), 'exec'), namespace)  # noqa: S102

    @pytest.mark.parametrize('column', GUIDE_COLUMNS)
    def test_the_guide_names_each_structured_column(self, column: str) -> None:
        assert f'`{column}`' in GUIDE.read_text()

    def test_the_guide_lists_every_opt_in_column_but_raw(self) -> None:
        assert opt_in_names() - {'raw'} == set(GUIDE_COLUMNS)


class TestSocColumns:
    def test_select_accepts_the_preset(self, mailbox_writer: MailboxWriter) -> None:
        drafts = [MessageDraft(sender='a@example.com', subject='s', body=['b'])]
        mailbox = Mailbox(mailbox_writer.write(drafts))
        assert mailbox.select(mboxturbo.SOC_COLUMNS).columns == list(
            mboxturbo.SOC_COLUMNS
        )

    def test_the_preset_covers_every_opt_in_column_the_catalogue_knows(self) -> None:
        assert opt_in_names() - {'raw'} <= set(mboxturbo.SOC_COLUMNS)

    def test_the_preset_is_exported(self) -> None:
        assert 'SOC_COLUMNS' in mboxturbo.__all__


def documented(owner: object, names: list[str]) -> list[str]:
    return [
        name
        for name in names
        if not (getattr(getattr(owner, name), '__doc__', None) or '').strip()
    ]


class TestDocstrings:
    @pytest.mark.parametrize(
        'name',
        [
            'Predicate',
            'HeaderBuilder',
            'VerdictBuilder',
            'Trust',
            'CancelToken',
            'Cancelled',
            'Selection',
            'Exporter',
            'header',
            'verdict',
        ],
    )
    def test_public_names_have_a_docstring(self, name: str) -> None:
        assert documented(mboxturbo, [name]) == []

    @pytest.mark.parametrize(
        ('name', 'methods'),
        [
            ('Predicate', ['__and__', '__or__', '__invert__', 'from_json', 'to_json']),
            (
                'HeaderBuilder',
                ['exists', 'equals', 'contains', 'startswith', 'matches'],
            ),
            ('VerdictBuilder', ['equals']),
            ('CancelToken', ['cancel', 'is_cancelled']),
            ('Selection', ['export', 'to_parquet', 'columns', 'excluded_undated']),
            ('Exporter', ['begin', 'write_batch', 'finish']),
            ('Mailbox', ['select']),
        ],
    )
    def test_public_methods_have_a_docstring(self, name: str, methods: list[str]) -> None:
        assert documented(getattr(mboxturbo, name), methods) == []
