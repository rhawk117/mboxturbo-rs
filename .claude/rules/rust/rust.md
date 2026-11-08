---
paths:
  - "crates/**/*.rs"
---

<scope>
Governs every Rust source file under `crates/` (the core `mboxturbo` crate and the `mboxturbo-py` PyO3 bindings, `src/` and `tests/`) when Claude reads, writes or edits it. Test-writing conventions live in `rust-tests.md` next to this file. Clippy (workspace lints in `Cargo.toml`, thresholds in `clippy.toml`) already denies unwrap, expect, panic, indexing, `as` casts, missing docs and overlong or complex functions; these conventions cover what those lints cannot judge. Carve-outs: convention 2 applies to the core crate only, since `mboxturbo-py` converts to `PyErr` at its boundary; convention 3 does not apply inside `#[cfg(test)]` modules or `tests/`, where a panic is a test failure; convention 7 yields where `#[pymethods]` require owned or `Py<T>` types.
</scope>

<conventions>
1. Never satisfy a lint by swallowing a failure: you must not use `unwrap_or_default`, `.ok()`, `unwrap_or_else(identity)` or `let _ =` on a value that signals an error or a broken invariant. Propagate it with `?`; where the default really is the correct answer, say why in `#[expect(clippy::disallowed_methods, reason = "...")]` on the enclosing `let` or `fn` (`clippy.toml` bans these methods), because a silent default turns corruption into plausible-looking wrong output. In tests the fix is `.expect("why this holds")`.
2. Every error variant must carry what a caller needs to act (file path, message position, byte offset or range), attached where that context exists, and the library crate must not use `String` or `Box<dyn Error>` as an error type, because callers match on variants and a forensic tool must say which message failed.
3. Use `checked_*` or `saturating_*` and handle the overflow case; you must use `strict_*` only where overflow is provably impossible, with the bound stated in `#[expect(clippy::disallowed_methods, reason = "...")]`, because `strict_*` panics and only moves the panic the lints were meant to remove.
4. Prefer enums and newtypes over bool flags, parallel `Option`s, or bare `usize` values whose meaning lives only in a variable name, because a type the compiler checks cannot be passed in the wrong slot.
5. Doc comments must state the contract (what the caller gets, the errors and when, invariants, edge cases such as clamping or empty input) and must not restate the item's name, because `missing_docs` forces a comment to exist and a name-echo adds nothing.
6. Prefer adding a trait, generic parameter, builder or config struct only once a second implementor or call site exists, because a single-use abstraction is indirection with no payoff.
7. Prefer borrowed inputs (`&str`, `&[u8]`, `impl AsRef<_>`) and borrowed or `Cow` outputs; do not `clone`, `to_string`, `to_owned` or `to_vec` just to satisfy the borrow checker or to store a `'static` literal, because this crate exists to avoid copying mailbox bytes.
8. Prefer flat functions: guard clauses and `let ... else` early returns instead of nested branches, and each distinct decision extracted into a small named function, because a small pure helper can be tested and proven on its own where one branchy function cannot.
</conventions>

<examples>
Convention 1, a default that hides a broken invariant:

```rust
// before
let raw = store.get(position).unwrap_or_default();
// after
let Some(raw) = store.get(position) else {
    // the index listed this position, so a miss means the index and the file disagree
    return Err(Error::corrupt(path, Corruption::Bounds));
};
```

Convention 2, an error that cannot say what failed:

```rust
// before
#[error("cannot assemble a batch")]
Batch { #[source] source: ArrowError },
// after
#[error("cannot assemble a batch for messages {}..{}", positions.start, positions.end)]
Batch { positions: Range<usize>, #[source] source: ArrowError },
```

Convention 3, untrusted input versus a proven bound:

```rust
// before: `len` comes from a file header
let end = start.strict_add(len);
// after
let end = start.checked_add(len).ok_or(Corruption::Bounds)?;

#[expect(clippy::disallowed_methods, reason = "zone_minutes() caps |offset| below 24 * 60, so * 60 fits in i64")]
let offset_seconds = i64::from(offset_minutes).strict_mul(60);
```

Convention 5:

```rust
// before
/// Snappy.
Snappy,
// after
/// Snappy: cheaper to decode than Zstd, at the cost of larger files.
Snappy,
```

Convention 8:

```rust
// before: three nested ifs repeated for '+' and '-'
// after
fn zone(token: &str) -> Option<i32> {
    let (sign, digits) = split_sign(token)?;
    let (hours, minutes) = four_digit_hhmm(digits)?;
    Some(sign * (hours * 60 + minutes))
}
```
</examples>

<anti_patterns>

- `.ok()`, `.unwrap_or_default()` or `.ok().flatten()` chained onto a fallible call to get past `unwrap_used` or `map_err_ignore`; propagate the error or state why the default is right. `.ok()?` inside a function returning `Option`, where `None` already means "not present", is correct but still needs the `#[expect]` reason, because the ban cannot tell the cases apart.
- `map_err(|source| Error::X { source })` at a site that knows the path or position but does not record it.
- A run of `strict_add`/`strict_mul` on values parsed from mailbox bytes or index headers.
- Doc comments that are the item name plus a full stop, or that describe the implementation instead of what the caller can rely on.
- A trait or generic with one implementor, added "for flexibility".
- `"literal".to_owned()` stored in an enum or struct field that could hold `&'static str` or `Cow<'static, str>`.
- When the function Claude is editing already breaks a convention, fix it in that function as part of the change; list violations seen elsewhere in the file in the final message instead of rewriting them.

</anti_patterns>

<verification>
Before finishing a change to a matching file, run `uv run prek run --files FILES` (rustfmt on the pinned nightly, clippy with the `clippy.toml` bans, rustdoc and the rule patterns), and read every new `#[expect(clippy::disallowed_methods, ...)]` reason: it must name the bound or the reason the default is correct, not restate the method. A reviewer can confirm by checking that each new error variant names the path or position it concerns and that each new doc comment says something its signature does not.
</verification>
