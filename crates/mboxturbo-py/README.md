# mboxturbo (Python)

Python bindings for the mboxturbo Rust crate: offset-indexed random access, parallel indexing and Rust-parsed messages for large mbox files. A mailbox is memory-mapped and indexed once, so `mailbox[i]` is a lookup and a header read parses only the header block. Requires CPython 3.14 or free-threaded 3.14t.

The main entry points are `Mailbox` (open, index, iterate, `select`), `Message` and `Attachment` (the parsed view), `header(...)` predicates for `Mailbox.select(where=...)`, and `Selection.export` for writing Arrow-based exports.

```python
from mboxturbo import Mailbox

with Mailbox('inbox.mbox') as mailbox:
    print(len(mailbox), mailbox[-1].subject)
    for message in mailbox:
        hops = message.get_all('Received')
```

Without `index=`, opening a mailbox saves its index beside it as `<mailbox path>.mbxidx` and reuses it while it matches. The command-line exporter, installed with `pip install "mboxturbo[cli]"`, uses the same sidecar.

The full documentation, including the Arrow and Parquet pipeline, is in the repository README: https://github.com/rhawk117/mboxturbo-rs
