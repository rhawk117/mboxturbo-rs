# mboxturbo

Rust rewrite of [MboxTurbo](https://github.com/rhawk117/mboxturbo): offset-indexed random access, parallel indexing and Rust-parsed messages for large mbox files, with Python bindings.

| Crate | What it is |
|---|---|
| `crates/mboxturbo` | Pure Rust core: mmap, SIMD `From ` scan split across rayon threads, fingerprinted index file, zero-copy two-tier lazy parsing via `mail-parser` |
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
| Read every `Subject` | ~41 s (`EmailMessage`) | 0.08 s | ~500x |
| Subject, sender, date, attachments | | 4.0 s lazy, 2.5 s `batches()` | |

The index scan runs at about 18 GB/s on two threads from a warm cache. Cold, a buffered `read()` scan beat mmap by about 38% in testing; the mmap path is kept because it is about 80% faster warm and a saved index skips the scan entirely.

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
UV_PROJECT_ENVIRONMENT=.venv-ft uv sync -p 3.14t && UV_PROJECT_ENVIRONMENT=.venv-ft uv run -p 3.14t pytest
```
