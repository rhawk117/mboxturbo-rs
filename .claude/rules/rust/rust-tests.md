---
paths:
  - "crates/**/*.rs"
---

<scope>
Governs Rust tests under `crates/`: integration tests in `crates/*/tests/*.rs` and inline `#[cfg(test)]` modules in `src/`, when Claude reads, writes or edits them. Code conventions live in `rust.md` next to this file; its convention 1 (no silent fallbacks) applies to tests too, and its convention 3 (`strict_*`) does not. `clippy.toml` already allows unwrap, expect, panic and indexing in tests, and `missing_assert_message` already requires a message on every assert.
</scope>

<conventions>
1. Every test must assert an outcome that a plausible broken implementation would get wrong, because a test that only runs code proves nothing; "does not panic" counts only when panic-freedom is the stated contract of the test or file.
2. Prefer one behavior per test, named as a sentence stating that behavior (`a_stale_cache_is_rebuilt_and_rewritten`, not `test_cache_2`), because a failing name should tell the reader what broke without opening the body.
3. Assert errors by variant with `matches!` or `assert_eq!` on the enum; you must not compare `Display` or `to_string()` output, because messages are reworded freely and variants are the contract.
4. Assert and `expect` messages must say what the expectation means (`"the last message runs to EOF"`, `"fixture mbox opens"`), not echo the call (`"open"`), because the lint forces a message and the message is what a failing run shows.
5. Prefer testing behavior through the public API in `tests/*.rs`; keep inline `#[cfg(test)]` modules for private invariants the public API cannot reach (index encoding, private parsers), because public-API tests survive refactors.
6. Prefer `proptest` for properties (round-trip, ordering, parallel equals sequential, never panics on arbitrary bytes) and example tests for specific cases, and pin every failure proptest finds as a named example test with the shrunk input inline, because a proptest seed is not a readable regression.
7. A regression test must name what broke (the upstream crate and version, or the issue number) in its assert message or a one-line comment, because otherwise the next cleanup deletes it as redundant.
</conventions>

<examples>
Conventions 1 and 2, a test that runs code versus one that pins a behavior:

```rust
// before
#[test]
fn parses_message() { exercise(&only_message(PLAIN)); }
// after
#[test]
fn an_encoded_word_subject_is_decoded() {
    assert_eq!(only_message(PLAIN).subject(), Some("café"), "RFC 2047 q-encoding is decoded");
}
```

Convention 3:

```rust
// before
assert!(error.to_string().contains("checksum"));
// after
assert!(
    matches!(error, Error::CorruptIndex { corruption: Corruption::Checksum, .. }),
    "a flipped byte fails the checksum",
);
```

Convention 4:

```rust
// before
let mailbox = Mailbox::open(&path).expect("open");
prop_assert!(message.parse() || message.subject().is_none());
// after
let mailbox = Mailbox::open(&path).expect("fixture mbox opens");
prop_assert!(message.parse() || message.subject().is_none(), "an unparsable message exposes no subject");
```

Convention 6:

```rust
proptest! {
    #[test]
    fn decode_inverts_encode(mbox in mailboxes()) {
        prop_assert_eq!(decode(&encode(&mbox)), mbox, "decode(encode(x)) == x");
    }
}

// found by proptest: a trailing zero-length message
#[test]
fn a_trailing_empty_message_round_trips() { /* shrunk input inline */ }
```
</examples>

<anti_patterns>

- A test whose body only calls accessors or wraps them in `black_box`, outside a file or test whose stated contract is panic-freedom.
- One test asserting several unrelated fields (subject, message id, sender, received headers); split it so each name states one behavior.
- `expect` or assert messages of one or two words that repeat the method name.
- `prop_assert!` or `prop_assert_eq!` with no message.
- An integration-level scenario (open a tempfile mailbox, build a cache) written as an inline unit test in `src/`.
- When the test Claude is editing already breaks a convention, fix that test as part of the change; list violations seen elsewhere in the file in the final message instead of rewriting them.

</anti_patterns>

<verification>
Before finishing a change to a test, run `uv run prek run --files FILES` (its deny-pattern hooks catch terse `expect` messages, bare `prop_assert!` and `Display` assertions) and `uv run prek run cargo-test --hook-stage manual`. Ask of each new test: which plausible bug makes this fail? A reviewer can confirm by reading each new test name alone and predicting what it asserts.
</verification>
