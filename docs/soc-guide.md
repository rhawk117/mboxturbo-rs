# SOC guide

How to triage a mailbox with mboxturbo: decide which hosts you trust, filter messages by
header and authentication verdict, pull the parsed authentication columns into Arrow, and
hand the rows to your own writer. Every `python` block below runs in order in one namespace
and is executed by the test suite, so the guide cannot drift from the API. `pyarrow` is
needed for the exporter block.

## A small mailbox

Build an mbox with three messages: one whose own relay vouches for DMARC, one carrying a
forged `Authentication-Results` from a host nobody trusts, and one with no `Date`.

```python
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pyarrow as pa

from mboxturbo import (
    SOC_COLUMNS,
    Cancelled,
    CancelToken,
    Mailbox,
    Predicate,
    Trust,
    header,
    verdict,
)

work = Path(tempfile.mkdtemp())


def message(subject: str, results: str, date: str | None) -> str:
    lines = ['From sender@example.org Mon Jan  1 00:00:00 2024']
    lines += [f'Authentication-Results: {results}', f'Subject: {subject}']
    lines += [f'Date: {date}'] if date else []
    return '\n'.join([*lines, '', 'body', '', ''])


mbox = work / 'inbox.mbox'
mbox.write_text(
    ''.join([
        message(
            'genuine',
            'mx.example.org; dmarc=pass header.from=example.org',
            'Mon, 01 Jan 2024 00:00:00 +0000',
        ),
        message(
            'forged',
            'evil.example; dmarc=pass header.from=example.org',
            'Tue, 02 Jan 2024 00:00:00 +0000',
        ),
        message('undated', 'mx.example.org; dmarc=fail header.from=example.org', None),
    ])
)
mailbox = Mailbox(mbox)
assert len(mailbox) == 3
```

## Building a Trust

An `Authentication-Results` header is only evidence when a relay you run wrote it, and any
sender can forge one. A `Trust` names the relays whose headers count. An empty `Trust`
trusts nothing.

- `hosts`: domains trusted along with their subdomains.
- `ip_ranges`: addresses or CIDR ranges such as `192.0.2.0/24`; a malformed range raises
  `ValueError` naming it and the byte offset.
- `authserv_ids`: the authserv-id an `Authentication-Results` header starts with, matched
  exactly and without regard to case.
- `trust_idless_inside`: Exchange Online writes `Authentication-Results` with no
  authserv-id, so an id cannot vouch for it. With this switch on, such a header is trusted
  only when it sits above the `Received` header of the first external hop, the newest hop
  whose `by` host is trusted and whose `from` host and address are not. A header below that
  hop, or in a message with no such hop, was added outside your relays and stays untrusted.
  The switch is off by default and never makes an empty authserv-id a trusted entry.

```python
trust = Trust(
    hosts=['example.org'],
    ip_ranges=['192.0.2.0/24'],
    authserv_ids=['mx.example.org'],
    trust_idless_inside=True,
)
only_mx = Trust(authserv_ids=['mx.example.org'])
```

## Predicates

`header(name)` matches the values of one header (names are case-insensitive) with
`exists()`, `equals(value)`, `contains(value)`, `startswith(value)` and `matches(pattern)`
(a regular expression found anywhere in the value). `verdict(method)` matches the trusted
result of `dmarc`, `spf`, `dkim` or `compauth` with `equals(result)`. Combine predicates
with `&` (both), `|` (either) and `~` (not). A predicate that cannot be built fails when
it is built, not when it runs. A `verdict` predicate never matches without a `Trust`.

`to_json()` gives the compact JSON form and `Predicate.from_json` reads it back, so a
hunt can be stored and shared; predicates compare equal when their JSON is equal.

```python
passing = verdict('dmarc').equals('pass')
suspicious = header('Subject').contains('forged') | ~header('Date').exists()
hunt = passing & ~suspicious
assert Predicate.from_json(hunt.to_json()) == hunt
```

## Structured columns

Pass these column names to `Mailbox.select`. They are opt-in: the default columns leave
them out.

| Column | Holds |
| --- | --- |
| `auth_results` | every `Authentication-Results` header parsed, with a `trusted` flag per header |
| `arc_sets` | the ARC chain grouped into sets by instance |
| `dkim_signatures` | every `DKIM-Signature` parsed |
| `received_hops` | the `Received` chain parsed, marking the first external hop |
| `received_spf_parsed` | `Received-SPF` parsed |
| `microsoft_antispam` | the Microsoft anti-spam headers parsed |

The `trusted` flags and the verdict columns below need a `Trust`; without one the flags
are null.

The verdict columns hold one result word (`pass`, `fail`, `none` ...) each:
`verdict_dmarc`, `verdict_spf`, `verdict_dkim` and `verdict_compauth`. They are null
without a `Trust`, and null when no trusted header carries that method, so a forged header
never sets a verdict.

`mboxturbo.SOC_COLUMNS` is the default columns plus every structured and verdict column,
for one call that selects them all:

```python
table = pa.table(mailbox.select(SOC_COLUMNS, trust=only_mx))
assert table.column('verdict_dmarc').to_pylist() == ['pass', None, 'fail']
untrusted = pa.table(mailbox.select(['verdict_dmarc']))
assert untrusted.column('verdict_dmarc').to_pylist() == [None, None, None]
```

## Selecting rows

`select(columns, *, positions=, since=, until=, where=, trust=)` keeps only the rows every
filter admits.

- `positions`: message numbers; sorted and deduplicated, and a position past the end
  raises `MboxTurboError` at `select`.
- `since`, `until`: keep `since <= date < until` on the index date; both must be
  timezone-aware. A message with no usable date is dropped, and
  `Selection.excluded_undated` counts them (0 without `since` or `until`).
- `where`: a `Predicate`.
- `trust`: the `Trust` that decides verdicts.

```python
selection = mailbox.select(
    ['position', 'subject', 'verdict_dmarc'],
    since=datetime(2024, 1, 1, tzinfo=UTC),
    until=datetime(2024, 1, 3, tzinfo=UTC),
    where=verdict('dmarc').equals('pass'),
    trust=only_mx,
)
assert pa.table(selection).column('subject').to_pylist() == ['genuine']
assert selection.excluded_undated == 1
```

## Parquet export, progress and cancel

`Selection.to_parquet(path, *, compression=, overwrite=, progress=, cancel=)` writes
atomically and returns the row count. An existing file raises `FileExistsError` unless
`overwrite=True`. The GIL is released while exporting. `progress(done, total)` runs after
each written batch.

Ctrl-C, `CancelToken.cancel()` from another thread, or a `progress` callback that raises
stops the export after its current batch, leaves no file and raises `Cancelled` caused by
the interrupt or by the callback's exception. A Ctrl-C or a raising callback cancels the
`CancelToken` you passed for good, so make a fresh token for every export instead of
reusing one.

```python
seen: list[tuple[int, int]] = []
target = work / 'hunt.parquet'
assert (
    mailbox.select(SOC_COLUMNS, trust=only_mx).to_parquet(
        target, progress=lambda done, total: seen.append((done, total))
    )
    == 3
)
assert seen[-1] == (3, 3)


def stop(done: int, total: int) -> None:
    raise RuntimeError('stop')


token = CancelToken()
try:
    mailbox.select(['position']).to_parquet(
        work / 'cut.parquet', progress=stop, cancel=token
    )
except Cancelled as error:
    assert isinstance(error.__cause__, RuntimeError)
assert token.is_cancelled
assert not (work / 'cut.parquet').exists()
```

## A Python exporter

`Selection.export(exporter, path, *, overwrite=, progress=, cancel=)` runs any object with
three methods and returns the row count. `begin(schema, out)` runs once, `write_batch(batch,
out)` once per batch and `finish(out)` once after the last; nothing reaches `path` unless
`finish` returns, and an exception from the exporter is raised as is after the staged
output is discarded. `schema` and `batch` expose the Arrow PyCapsule interface, so
`pyarrow.schema(schema)` and `pyarrow.record_batch(batch)` import them without a copy.

Its optional `kind` attribute picks what `out` is: `'file'` (the default) gives an object
with `write(data)` whose bytes become the target file, and `'directory'` gives the staging
`pathlib.Path` that becomes the target directory.

```python
class LineExporter:
    kind = 'file'

    def begin(self, schema, out, /):
        out.write(','.join(pa.schema(schema).names).encode() + b'\n')

    def write_batch(self, batch, out, /):
        for row in pa.record_batch(batch).to_pylist():
            out.write(','.join(map(str, row.values())).encode() + b'\n')

    def finish(self, out, /):
        out.write(b'# end\n')


report = work / 'report.csv'
rows = mailbox.select(
    ['subject', 'verdict_dmarc'],
    where=header('Subject').startswith('gen') | verdict('dmarc').equals('fail'),
    trust=only_mx,
).export(LineExporter(), report)
assert rows == 2
assert report.read_text() == 'subject,verdict_dmarc\ngenuine,pass\nundated,fail\n# end\n'
```
