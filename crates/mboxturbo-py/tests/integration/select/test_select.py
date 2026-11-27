"""Mailbox.select narrows rows by position, index date, predicate and trust."""

from datetime import UTC, datetime, timedelta, timezone

import pyarrow as pa
import pytest

from mboxturbo import Mailbox, MboxTurboError, Trust, header, verdict
from mboxturbo.tests.drafts import MailboxWriter

pl = pytest.importorskip('polars')
pytestmark = pytest.mark.integration

AUTHSERV_ID = 'mx.example.org'
FORGED = 'Authentication-Results: evil.example; dmarc=pass header.from=example.org\n'
GENUINE = f'Authentication-Results: {AUTHSERV_ID}; dmarc=fail header.from=example.org\n'
PASSING = f'Authentication-Results: {AUTHSERV_ID}; dmarc=pass header.from=example.org\n'
JAN_1 = datetime(2024, 1, 1, tzinfo=UTC)
JAN_2 = datetime(2024, 1, 2, tzinfo=UTC)
JAN_3 = datetime(2024, 1, 3, tzinfo=UTC)
UNDATED = [3, 5]


def message(*lines: str) -> str:
    return '\n'.join([
        'From a@example.com Mon Jan  1 00:00:00 2024',
        *lines,
        '',
        'body',
        '',
        '',
    ])


# Positions 0..5; position 2 is dated 2024-01-03 00:00:00 UTC, position 4 in +0100.
MAILBOX = ''.join([
    message('Date: Mon, 01 Jan 2024 00:00:00 +0000', 'Subject: zero', FORGED + GENUINE),
    message('Date: Tue, 02 Jan 2024 00:00:00 +0000', 'Subject: one', PASSING),
    message('Date: Wed, 03 Jan 2024 00:00:00 +0000', 'Subject: two', FORGED),
    message('Subject: three'),
    message('Date: Thu, 04 Jan 2024 00:00:00 +0100', 'Subject: four'),
    message('Subject: five'),
])


@pytest.fixture
def mailbox(mailbox_writer: MailboxWriter) -> Mailbox:
    return Mailbox(mailbox_writer.write_raw(MAILBOX.encode()))


def kept(selection: object) -> list[int]:
    return pa.table(selection).column('position').to_pylist()


class TestPositions:
    def test_no_filter_keeps_every_row(self, mailbox: Mailbox) -> None:
        selection = mailbox.select(['position'])
        assert kept(selection) == [0, 1, 2, 3, 4, 5]
        assert selection.excluded_undated == 0

    def test_positions_are_sorted_and_deduplicated(self, mailbox: Mailbox) -> None:
        assert kept(mailbox.select(['position'], positions=[4, 1, 4, 0])) == [0, 1, 4]

    def test_positions_past_the_end_raise_at_select(self, mailbox: Mailbox) -> None:
        with pytest.raises(MboxTurboError, match='position 6 is out of range'):
            mailbox.select(positions=[0, 6])

    def test_a_position_the_date_range_drops_is_still_validated(
        self, mailbox: Mailbox
    ) -> None:
        with pytest.raises(MboxTurboError, match='out of range'):
            mailbox.select(positions=[99], since=JAN_3)

    def test_parquet_writes_only_the_selected_rows(
        self, mailbox: Mailbox, tmp_path_factory: pytest.TempPathFactory
    ) -> None:
        target = tmp_path_factory.mktemp('select').joinpath('rows.parquet')
        written = mailbox.select(['position'], positions=[5, 3]).to_parquet(target)
        assert written == len(UNDATED)
        assert pl.read_parquet(target)['position'].to_list() == UNDATED

    def test_polars_reads_the_selected_rows(self, mailbox: Mailbox) -> None:
        frame = pl.DataFrame(mailbox.select(['position', 'subject'], positions=[2, 0]))
        assert frame.to_dicts() == [
            {'position': 0, 'subject': 'zero'},
            {'position': 2, 'subject': 'two'},
        ]

    def test_the_repr_counts_the_kept_rows(self, mailbox: Mailbox) -> None:
        selection = mailbox.select(['position'], positions=[1, 2])
        assert repr(selection) == 'Selection(columns=1, messages=2)'


class TestDateRange:
    def test_since_is_inclusive_to_the_second_and_until_exclusive(
        self, mailbox: Mailbox
    ) -> None:
        both = mailbox.select(['position'], since=JAN_2, until=JAN_3)
        assert kept(both) == [1]
        just_after = JAN_2 + timedelta(seconds=1)
        assert kept(mailbox.select(['position'], since=just_after)) == [2, 4]
        just_before = JAN_2 - timedelta(seconds=1)
        assert kept(mailbox.select(['position'], until=just_before)) == [0]

    def test_fractional_bounds_round_up_to_the_next_whole_second(
        self, mailbox: Mailbox
    ) -> None:
        fraction = JAN_2 + timedelta(microseconds=1)
        assert kept(mailbox.select(['position'], since=fraction)) == [2, 4]
        assert kept(mailbox.select(['position'], until=fraction)) == [0, 1]

    def test_open_bounds_leave_that_side_unbounded(self, mailbox: Mailbox) -> None:
        assert kept(mailbox.select(['position'], since=JAN_3)) == [2, 4]
        assert kept(mailbox.select(['position'], until=JAN_2)) == [0]

    def test_bounds_compare_instants_not_wall_clocks(self, mailbox: Mailbox) -> None:
        midnight = datetime(2024, 1, 4, tzinfo=timezone(timedelta(hours=1)))
        assert kept(mailbox.select(['position'], since=midnight)) == [4]
        assert kept(mailbox.select(['position'], since=midnight, until=midnight)) == []

    def test_a_bound_counts_the_undated_messages_it_dropped(
        self, mailbox: Mailbox
    ) -> None:
        assert mailbox.select(since=JAN_1).excluded_undated == len(UNDATED)
        assert mailbox.select(until=JAN_1).excluded_undated == len(UNDATED)


class TestPredicate:
    def test_a_predicate_keeps_the_matching_rows(self, mailbox: Mailbox) -> None:
        selection = mailbox.select(['position'], where=header('subject').contains('o'))
        assert kept(selection) == [0, 1, 2, 4]

    def test_filters_intersect(self, mailbox: Mailbox) -> None:
        selection = mailbox.select(
            ['position'],
            positions=[0, 1, 2, 4, 5],
            since=JAN_3,
            where=header('subject').contains('o'),
        )
        assert kept(selection) == [2, 4]


class TestTrust:
    TRUST = Trust(authserv_ids=[AUTHSERV_ID])

    def test_verdict_columns_are_null_without_trust(self, mailbox: Mailbox) -> None:
        column = pa.table(mailbox.select(['verdict_dmarc'])).column('verdict_dmarc')
        assert column.to_pylist() == [None] * len(mailbox)

    def test_trust_decides_the_verdict_column_and_ignores_a_forged_header(
        self, mailbox: Mailbox
    ) -> None:
        selection = mailbox.select(['verdict_dmarc'], trust=self.TRUST)
        column = pa.table(selection).column('verdict_dmarc')
        assert column.to_pylist() == ['fail', 'pass', None, None, None, None]

    def test_verdict_predicates_never_match_without_trust(self, mailbox: Mailbox) -> None:
        selection = mailbox.select(['position'], where=verdict('dmarc').equals('pass'))
        assert kept(selection) == []

    def test_trust_decides_the_verdict_predicate_and_ignores_a_forged_header(
        self, mailbox: Mailbox
    ) -> None:
        selection = mailbox.select(
            ['position'], where=verdict('dmarc').equals('pass'), trust=self.TRUST
        )
        assert kept(selection) == [1]


class TestArgumentTypes:
    def test_naive_bounds_ask_for_a_tzinfo(self, mailbox: Mailbox) -> None:
        naive = datetime(2024, 1, 2)  # noqa: DTZ001
        with pytest.raises(TypeError, match='tzinfo'):
            mailbox.select(since=naive)
        with pytest.raises(TypeError, match='tzinfo'):
            mailbox.select(until=naive)

    def test_other_argument_types_raise_type_error(self, mailbox: Mailbox) -> None:
        with pytest.raises(TypeError):
            mailbox.select(since='2024-01-02')  # ty: ignore[invalid-argument-type]
        with pytest.raises(TypeError):
            mailbox.select(where='subject')  # ty: ignore[invalid-argument-type]
        with pytest.raises(TypeError):
            mailbox.select(trust=['mx.example.org'])  # ty: ignore[invalid-argument-type]
