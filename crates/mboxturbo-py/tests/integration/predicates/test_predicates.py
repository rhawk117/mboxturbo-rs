"""Predicate builders and Trust: JSON forms, operators, eager validation, round trips."""

import json
import operator
from collections.abc import Callable

import pytest
from hypothesis import given
from hypothesis import strategies as st

from mboxturbo import MboxTurboError, Predicate, Trust, header, verdict

pytestmark = pytest.mark.integration

EXISTS_LIST_ID = '{"op":"exists","header":"list-id"}'
EXISTS_X = '{"op":"exists","header":"x"}'

BUILDER_JSON = [
    (header('list-id').exists(), EXISTS_LIST_ID),
    (
        header('x-spam-flag').equals('YES'),
        '{"op":"equals","header":"x-spam-flag","value":"YES"}',
    ),
    (
        header('subject').contains('invoice'),
        '{"op":"contains","header":"subject","value":"invoice"}',
    ),
    (
        header('from').startswith(b'billing@'),
        '{"op":"starts_with","header":"from","value":"billing@"}',
    ),
    (
        header('subject').matches('^Re: .*[0-9]{4}$'),
        '{"op":"regex","header":"subject","pattern":"^Re: .*[0-9]{4}$"}',
    ),
    (
        verdict('dmarc').equals('pass'),
        '{"op":"verdict","method":"dmarc","equals":"pass"}',
    ),
    (
        header('list-id').exists() & header('x').exists(),
        f'{{"op":"and","args":[{EXISTS_LIST_ID},{EXISTS_X}]}}',
    ),
    (
        header('list-id').exists() | header('x').exists(),
        f'{{"op":"or","args":[{EXISTS_LIST_ID},{EXISTS_X}]}}',
    ),
    (~header('list-id').exists(), f'{{"op":"not","arg":{EXISTS_LIST_ID}}}'),
]


@pytest.mark.parametrize(('predicate', 'expected'), BUILDER_JSON)
def test_builder_json_matches_documented_form(
    predicate: Predicate, expected: str
) -> None:
    assert predicate.to_json() == expected
    assert Predicate.from_json(expected) == predicate


@pytest.mark.parametrize('method', ['dmarc', 'spf', 'dkim', 'compauth'])
def test_verdict_accepts_each_method(method: str) -> None:
    built = verdict(method).equals('fail')
    assert json.loads(built.to_json()) == {
        'op': 'verdict',
        'method': method,
        'equals': 'fail',
    }


def test_and_or_flatten_nested_operands() -> None:
    a, b, c = (header(name).exists() for name in 'abc')
    flat = json.loads(((a & b) & c).to_json())
    assert [arg['header'] for arg in flat['args']] == ['a', 'b', 'c']
    assert json.loads((a | (b | c)).to_json())['op'] == 'or'
    assert len(json.loads((a | (b | c)).to_json())['args']) == len('abc')
    mixed = json.loads(((a | b) & c).to_json())
    assert mixed['op'] == 'and'
    assert mixed['args'][0]['op'] == 'or'


def test_str_and_bytes_are_equivalent() -> None:
    assert header('subject').equals('café') == header('subject').equals('café'.encode())


def test_bytes_that_are_not_utf8_raise_value_error() -> None:
    with pytest.raises(ValueError, match='UTF-8'):
        header('subject').equals(b'\xff')


def test_verdict_rejects_unknown_method() -> None:
    with pytest.raises(ValueError, match='dmarc, spf, dkim, compauth'):
        verdict('arc')


def test_header_rejects_empty_name() -> None:
    with pytest.raises(ValueError, match='empty'):
        header('')


def test_matches_rejects_bad_pattern_with_base_error() -> None:
    with pytest.raises(MboxTurboError, match=r'\(') as raised:
        header('subject').matches('(')
    assert type(raised.value) is MboxTurboError


@pytest.mark.parametrize('combine', [operator.and_, operator.or_])
def test_combining_with_a_non_predicate_raises_type_error(
    combine: Callable[[object, object], object],
) -> None:
    predicate = header('x').exists()
    with pytest.raises(TypeError):
        combine(predicate, 1)


@pytest.mark.parametrize(
    'text',
    [
        '{"op":"and","args":[]}',
        '{"op":"or","args":[]}',
        '{"op":"regex","header":"s","pattern":"("}',
        '{"op":"nope"}',
        'not json',
    ],
)
def test_from_json_validates(text: str) -> None:
    with pytest.raises(MboxTurboError):
        Predicate.from_json(text)


def test_equality_and_repr() -> None:
    assert header('x').exists() == header('X'.lower()).exists()
    assert header('x').exists() != header('y').exists()
    assert header('x').exists() != 'x'
    assert repr(header('x').exists()) == f'Predicate({EXISTS_X})'


names = st.text(alphabet='abcdefgh-', min_size=1, max_size=6)
words = st.text(alphabet='abc XYZ', max_size=6)
leaves = st.one_of(
    names.map(lambda name: header(name).exists()),
    st.builds(lambda n, v: header(n).equals(v), names, words),
    st.builds(lambda n, v: header(n).contains(v), names, words),
    st.builds(lambda n, v: header(n).startswith(v), names, words),
    st.builds(
        lambda n, v: header(n).matches(v), names, st.sampled_from(['a+', '^b$', '[ab]'])
    ),
    st.builds(
        lambda m, v: verdict(m).equals(v),
        st.sampled_from(['dmarc', 'spf', 'dkim', 'compauth']),
        st.sampled_from(['pass', 'fail', 'none']),
    ),
)
trees = st.recursive(
    leaves,
    lambda inner: st.one_of(
        inner.map(lambda p: ~p),
        st.builds(lambda a, b: a & b, inner, inner),
        st.builds(lambda a, b: a | b, inner, inner),
    ),
    max_leaves=8,
)


@given(trees)
def test_built_trees_round_trip_through_json(predicate: Predicate) -> None:
    text = predicate.to_json()
    restored = Predicate.from_json(text)
    assert restored == predicate
    assert restored.to_json() == text


def test_trust_builds_with_every_option() -> None:
    assert isinstance(
        Trust(
            hosts=['mx.example.org'],
            ip_ranges=('192.0.2.0/24', '2001:db8::/32', '198.51.100.7'),
            authserv_ids=['mx.example.org'],
            trust_idless_inside=True,
        ),
        Trust,
    )
    assert isinstance(Trust(), Trust)


@pytest.mark.parametrize(
    ('bad', 'offset'),
    [('not-an-ip', 0), ('192.0.2.0/33', 10), ('2001:db8::/x', 11), ('1.2.3.4/', 8)],
)
def test_trust_rejects_malformed_range(bad: str, offset: int) -> None:
    with pytest.raises(ValueError, match=f'{bad}.*byte {offset}'):
        Trust(ip_ranges=['192.0.2.1', bad])


def test_trust_is_frozen_and_keyword_only() -> None:
    trust = Trust()
    with pytest.raises(AttributeError):
        trust.hosts = ()  # ty: ignore[unresolved-attribute]
    with pytest.raises(TypeError):
        Trust(['mx.example.org'])  # ty: ignore[too-many-positional-arguments]
