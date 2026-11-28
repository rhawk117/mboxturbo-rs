"""The named groups of ``column_names``."""

import pytest

import mboxturbo

pytestmark = pytest.mark.integration


class TestColumnNames:
    def test_the_default_group_is_all(self) -> None:
        assert mboxturbo.column_names() == mboxturbo.column_names(group='all')

    def test_defaults_and_opt_in_are_disjoint_parts_of_all(self) -> None:
        defaults = mboxturbo.column_names(group='defaults')
        opt_in = mboxturbo.column_names(group='opt_in')

        assert not set(defaults) & set(opt_in)
        assert set(defaults) | set(opt_in) < set(mboxturbo.column_names(group='all'))

    def test_all_keeps_catalogue_order(self) -> None:
        everything = mboxturbo.column_names(group='all')
        defaults = mboxturbo.column_names(group='defaults')

        assert [name for name in everything if name in defaults] == defaults

    def test_raw_is_opt_in(self) -> None:
        assert 'raw' in mboxturbo.column_names(group='opt_in')
        assert 'raw' not in mboxturbo.column_names(group='defaults')

    @pytest.mark.parametrize('group', ['', 'ALL', 'default', 'opt-in'])
    def test_an_unknown_group_names_the_allowed_ones(self, group: str) -> None:
        with pytest.raises(ValueError, match=r"'all', 'defaults' or 'opt_in'"):
            mboxturbo.column_names(group=group)  # ty: ignore[invalid-argument-type]
