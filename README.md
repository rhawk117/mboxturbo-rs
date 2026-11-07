# mboxturbo

Rust rewrite of [MboxTurbo](https://github.com/rhawk117/mboxturbo): offset-indexed random access, parallel indexing and Rust-parsed messages for large mbox files, with Python bindings.

| Crate | What it is |
|---|---|
| `crates/mboxturbo` | Pure Rust core: mmap, SIMD `From ` scan split across rayon threads, fingerprinted index file, zero-copy two-tier lazy parsing via `mail-parser`, and a columnar pipeline into Arrow batches and Parquet |
| `crates/mboxturbo-py` | Thin PyO3 layer (`import mboxturbo`), CPython 3.14 and free-threaded 3.14t |

## Python

```python
from mboxturbo import Mailbox

with Mailbox('inbox.mbox', index='inbox.mbxidx') as mailbox:
    print(len(mailbox), mailbox[-1].subject)

    for message in mailbox:
        hops = message.get_all('Received')

    for batch in mailbox.batches(1_000):
        for message in batch:
            payloads = [attachment.data for attachment in message.attachments]
```

- `index=` is a cache file: reused while it matches the mailbox, rebuilt and rewritten when missing or stale, and `CorruptIndexError` (file left untouched) when damaged.
- Header fields (`subject`, `from_`, `to`, `cc`, `date`, `message_id`, `get`, `get_all`) parse the header block only. Bodies and attachments trigger the full MIME parse.
- `batches()` decodes bodies and attachments in parallel. For header-only passes, plain iteration is faster.
- Iterators are safe to share between threads; each `next` claims a distinct message or batch.
- `get` and `get_all` return raw, unfolded values; encoded words stay as written. `subject` and the address fields are decoded.
- `to_email_message()` hands the same bytes to `email.message_from_bytes` for code that needs `EmailMessage`.
- A message the parser cannot handle, including input that panics mail-parser 0.11.2, reads as empty fields instead of raising; the rest of the mailbox is unaffected. `Received` headers are kept raw, and numeric `Date` zones past twelve hours (`+1300`, `+1400`) are read from the header because mail-parser 0.11.2 wraps them.
- Parallel work uses a thread pool that does not survive `os.fork()`; use the `forkserver` (the 3.14 default) or `spawn` start method.

## Pipeline: Arrow and Parquet

```python
import duckdb
import polars as pl
import pyarrow as pa

selection = mailbox.select(['from', 'subject', 'date', 'received', 'attachment_sha256'])
table = pa.table(selection)
frame = pl.DataFrame(selection)
duckdb.sql('select subject, len(received) as hops from selection')
selection.to_parquet('inbox.parquet', compression='zstd')
```

- `select` returns a reusable selection that any Arrow consumer reads through `__arrow_c_stream__` (verified with pyarrow 26, polars 2.1, DuckDB 2.0, and pandas 3.1 through `DataFrame.from_arrow`). Every read extracts in parallel in Rust; no Python object is created per message.
- Parsing follows the projection: `position`, `offset` and `size` read only the index, header columns run a header-only parser that skips every header no column needs, and only body or attachment columns pay for the full MIME parse.
- Columns: `position`, `offset`, `size`, `from`, `to`, `cc`, `reply_to`, `subject`, `date` (UTC, microseconds), `date_offset_minutes`, `message_id`, `received`, `authentication_results`, `received_spf`, `dkim_signature`, `return_path`, `text`, `html`, `attachment_names`, `attachment_types`, `attachment_sizes`, `attachment_sha256`, and `header:<Name>` for the raw values of any header. With no argument, `select()` takes every column that needs only headers.
- `to_parquet` writes atomically while the next batches are extracted on other threads; `compression` is `zstd` (default, level 1), `snappy` or `none`.

## Rust

```rust
let mailbox = mboxturbo::Mailbox::open_cached("inbox.mbox", "inbox.mbxidx")?;
let total_bytes: usize = mailbox.par_iter().map(<[u8]>::len).sum();
let message = mailbox.message(0).expect("non-empty");
let received: Vec<_> = message.header_values("Received").collect();
```

## Benchmarks

2.23 GB synthetic mbox, 50,000 messages (15% with base64 attachments up to 400 KB), page cache warm, 2 cores, CPython 3.14.

| Operation | Python MboxTurbo | mboxturbo | Speedup |
|---|---|---|---|
| Build index | 3.94 s | 0.18 s | 22x |
| Open with a saved index | unvalidated import | < 1 ms, validated | |
| Iterate raw bytes | 0.94 s | 0.25 s | 3.8x |
| 10k random reads | 0.100 s | 0.066 s | 1.5x |
| Read every `Subject` | ~41 s (`EmailMessage`) | 0.08 s per object, 0.017 s as a column | ~500x to ~2,400x |
| Subject, sender, date, attachments | | 2.3 s lazy, 1.6 s `batches()` | |
| 16 header columns to Arrow | | 0.047 s | |
| All 22 columns to Arrow (bodies, SHA-256) | | 1.8 s | |
| All 22 columns to Parquet (zstd) | | 2.5 s, 68 MB | |

The index scan runs at about 18 GB/s on two threads from a warm cache. Cold, a buffered `read()` scan beat mmap by about 38% in testing; the mmap path is kept because it is about 80% faster warm and a saved index skips the scan entirely.

## Vendored mail-parser

`vendor/mail-parser` is mail-parser 0.11.2 (Apache-2.0 OR MIT) with three hot loops replaced, wired in through `[patch.crates-io]`:

- `decode_base64_mime` finds the closing delimiter with SIMD `memmem` and decodes the span with `base64-simd`, falling back to the original byte loop for anything the strict decoder would treat differently (`=` before the end, a stray `-`, a form feed, a length that is not a multiple of four).
- `mime_part` and `seek_next_part` find `--<boundary>` with `memmem` instead of a byte loop.

Each replacement is checked against the original loop on 200,000 generated inputs (`cargo test --features serde,full_encoding` inside the vendored crate), and mail-parser's own corpus tests still pass. Re-apply the three functions when moving to mail-parser 1.x.

## Development

The workspace denies warnings, clippy `all`, `pedantic`, `nursery` and `cargo`, and 48 restriction lints. `unsafe` is denied except for the single read-only mmap call.

```sh
cargo fmt --check
cargo clippy --workspace --all-targets
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
cargo test --workspace

cd crates/mboxturbo-py
uv sync
uv run ruff format --check . && uv run ruff check . && uv run ty check src tests
uv run pytest
UV_PROJECT_ENVIRONMENT=.venv-ft uv sync -p 3.14t --no-group polars
UV_PROJECT_ENVIRONMENT=.venv-ft uv run -p 3.14t --no-group polars pytest
```
