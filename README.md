# mboxturbo

Rust rewrite of [MboxTurbo](https://github.com/rhawk117/mboxturbo): offset-indexed random access, parallel indexing and Rust-parsed messages for large mbox files, with Python bindings.

| Crate | What it is |
|---|---|
| `crates/mboxturbo` | Pure Rust core: mmap, SIMD `From ` scan split across rayon threads, fingerprinted, block-verified index mapped beside the mbox, zero-copy two-tier lazy parsing via `mail-parser`, and a columnar pipeline into Arrow batches and Parquet |
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

- Without `index=`, the index is saved beside the mailbox as `<mailbox path>.mbxidx` (`inbox.mbox` gets `inbox.mbox.mbxidx`) and reused while it matches. Anyone who can write the mailbox's directory controls that path, so the file is trusted only when it is a regular file owned by the mailbox's owner: a symlink, FIFO or foreign-owned file is never mapped and is replaced by a rebuilt index. A directory that cannot be written leaves nothing behind and the index stays in memory.
- `index=` names the cache file explicitly: reused while it matches the mailbox, rebuilt and rewritten when missing or stale, and `CorruptIndexError` (file left untouched) when its header is damaged.
- The index is mapped rather than loaded: each block is verified on first use, and a damaged block triggers a rescan and a rewrite instead of an error.
- Header fields (`subject`, `from_`, `to`, `cc`, `date`, `message_id`, `get`, `get_all`) parse the header block only. Bodies and attachments trigger the full MIME parse.
- `batches()` decodes bodies and attachments in parallel. For header-only passes, plain iteration is faster.
- Iterators are safe to share between threads; each `next` claims a distinct message or batch.
- `get` and `get_all` return raw, unfolded values; encoded words stay as written. `subject` and the address fields are decoded.
- `to_email_message()` hands the same bytes to `email.message_from_bytes` for code that needs `EmailMessage`.
- A message the parser cannot handle, including input that makes the parser panic, never raises: bodies and attachments read as empty, and header fields keep whatever the header-only parse recovers; the rest of the mailbox is unaffected. `Received` headers are kept raw, and numeric `Date` zones past twelve hours (`+1300`, `+1400`) are read from the header itself rather than from the parsed zone.
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

`Mailbox::open` keeps the index beside the mailbox by default; `MailboxBuilder` picks the policy (`IndexPolicy::Sidecar`, `Path` or `Memory`) and the block size.

## Benchmarks

2.23 GB synthetic mbox, 50,000 messages (15% with base64 attachments up to 400 KB), page cache warm, 2 cores, CPython 3.14.

| Operation | Python MboxTurbo | mboxturbo | Speedup |
|---|---|---|---|
| Build index | 3.94 s | 0.18 s | 22x |
| Open with a saved index | unvalidated import | < 1 ms, validated | |
| Iterate raw bytes | 0.94 s | 0.25 s | 3.8x |
| 10k random reads | 0.100 s | 0.066 s | 1.5x |

The index scan runs at about 18 GB/s on two threads from a warm cache. Cold, a buffered `read()` scan beat mmap by about 38% in testing; the mmap path is kept because it is about 80% faster warm and a saved index skips the scan entirely.

## Development

The workspace denies warnings, clippy `all`, `pedantic`, `nursery` and `cargo`, and the whole `restriction` group except the lints that contradict another lint or a convention in `.claude/rules/rust/` (each listed with its reason in `Cargo.toml`). `clippy.toml` holds ruff-parity thresholds and the banned methods; `prek.toml` wires every check. `unsafe` is denied except for the single read-only mmap call.

```sh
cargo fmt --check
cargo clippy --workspace --all-targets
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
cargo test --workspace

uv sync
uv run prek install          # pre-commit, commit-msg and pre-push hooks
uv run prek run --all-files  # every lint: rustfmt, clippy, rustdoc, cargo-deny, ruff, ty, typos, taplo...
uv run pytest
UV_PROJECT_ENVIRONMENT=.venv-ft uv sync -p 3.14t --no-group polars
UV_PROJECT_ENVIRONMENT=.venv-ft uv run -p 3.14t --no-group polars pytest
```

## CI and releases

Workflows follow the same shape as `mightymodels`:
- `ci.yml` runs on pull requests to `main` and as a reusable workflow. Lint: `uv run prek run --all-files` (rustfmt, clippy, rustdoc, cargo-deny, cargo-machete, ruff, ty, typos, taplo, shellcheck, actionlint, zizmor). Rust: tests. Python on 3.14 and 3.14t: pytest, plus a `pysentry` audit. It also runs the labeler and the workflow narrator.
- `cd.yml` (Release) is a manual dispatch from `main` with `recover`, `patch`, `minor` or `major`. It runs CI, then `.github/scripts/release.sh` bumps `pyproject.toml` (the version source of truth) and syncs the Cargo workspace version and both lockfiles. It commits, tags and pushes atomically, builds abi-specific wheels for CPython 3.14 and 3.14t on Linux x86_64/aarch64, macOS arm64/x86_64 and Windows x64, and attaches them to the GitHub Release.
- `weekly-security-scan.yml` audits the uv lockfile with `pysentry` and Cargo dependencies against RustSec, then opens or updates a tracking issue.

Before the first release:
1. Set the repository variable `UV_VERSION`.
2. Push the bootstrap tag. `release.sh` requires the previous release's tag:

```sh
git tag -a v0.1.0 -m "Release v0.1.0" && git push origin v0.1.0
```
