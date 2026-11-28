# mboxturbo CLI

`mboxturbo` exports large mbox files to analysis-friendly formats from the command line. It has three subcommands: `export`, `info` and `show`.

All example output on this page comes from the built binary or from a test named in the comment beside it. The examples use a four-message mailbox called `mail.mbox`. Unless an example says otherwise, none of its messages has a `Date:` header.

## Install

The package is not on PyPI. Download the wheels from the GitHub Release into a directory, then point `--find-links` at it:

```sh
pip install --find-links wheels "mboxturbo[cli]"
```

<!-- Source: .github/workflows/ci.yml installs the same way, with uv pip install --no-index --find-links wheels "mboxturbo[cli]". -->

To build the binary from a checkout instead:

```sh
cargo install --path crates/mboxturbo-cli
```

<!-- Source: crates/mboxturbo-cli/Cargo.toml (the mboxturbo bin target), installed from a checkout by cargo install --path. -->

To find the binary from Python, call `mboxturbo.find_mboxturbo_bin()`. It searches the interpreter's scripts directory, the user scripts directory and the scripts directory beside the package. It does not read `PATH`. When nothing is found it raises `mboxturbo.MboxTurboBinNotFoundError`, a `FileNotFoundError` that also derives from `MboxTurboError`.

```python
import subprocess

import mboxturbo

binary = mboxturbo.find_mboxturbo_bin()
subprocess.run([binary, "info", "mail.mbox"], check=True)
```

<!-- Source: crates/mboxturbo-py/src/mboxturbo/_bin.py and crates/mboxturbo-py/tests/integration/packaging/test_find_bin.py. -->

## Commands and flags

```text
mboxturbo [OPTIONS] <COMMAND>
```

<!-- Source: ./target/debug/mboxturbo --help -->

### Global flags

These flags are accepted before or after the subcommand.

| Flag | Meaning |
|------|---------|
| `--json` | Write a versioned JSON Lines event stream on standard output instead of human text. See [JSON events](#json-events). |
| `-q`, `--quiet` | Print no progress bar, summary line or index note on standard error. Errors still print. `--json` implies it. |
| `-h`, `--help` | Print help. |
| `-V`, `--version` | Print the version. |

### Colour

There is no colour flag. The choice comes from the environment and applies to help, usage errors and the progress bar together. The first rule that matches wins:

1. `NO_COLOR` set to a non-empty value turns colour off.
2. `CLICOLOR_FORCE` set to a non-empty value other than `0` turns colour on.
3. `CLICOLOR=0` turns colour off.
4. Otherwise colour is on when standard error is a terminal.

<!-- Source: crates/mboxturbo-cli/tests/progress.rs (forced_styling_reaches_clap_and_the_bar_line, no_color_beats_forced_styling) and src/progress.rs. -->

### `export`

```text
mboxturbo export [OPTIONS] --format <FORMAT> --output <OUT> <MAILBOX>
```

<!-- Source: ./target/debug/mboxturbo export --help -->

| Argument or flag | Meaning |
|------------------|---------|
| `<MAILBOX>` | The mbox file to export. |
| `--format <FORMAT>` | Required. One of `arrow`, `csv`, `eml`, `jsonl`, `mbox`, `parquet`. |
| `-o`, `--output <OUT>` | Required. A file, a directory for `eml`, or `-` for standard output. |
| `--columns <NAME,...>` | Columns to write, comma-separated. `header:<Name>` selects any header. Default: every column that needs no body parsing. |
| `--select <SPEC>` | Messages to export. Repeatable. Default: every message. |
| `--select-file <FILE>` | A file of selections, one spec per line. Blank lines are ignored. |
| `--since <WHEN>` | Keep only messages dated at or after `WHEN`. See [Date bounds](#date-bounds). |
| `--until <WHEN>` | Keep only messages dated before `WHEN`. See [Date bounds](#date-bounds). |
| `--where <JSON>` | Keep only messages matching a predicate in its JSON form. See [Predicates](#predicates). |
| `--where-file <PATH>` | A file holding the predicate, as for `--where`. Conflicts with `--where`. |
| `--index <PATH>` | Keep the message index in this file instead of beside the mailbox. |
| `--overwrite` | Replace the output if it already exists. Without it an existing output is refused with exit 73 and left unchanged. Even with it, a directory where a file goes, a file where a directory goes, and a directory that is not empty and holds no `manifest.jsonl` from an earlier export are refused with exit 73 and left unchanged. |

An export prints one summary line on standard error, preceded by `mboxturbo: index rebuilt` when the index had to be built:

```console
$ mboxturbo export mail.mbox --format csv --columns position,subject -o out.csv
exported 4 messages, 31 bytes to out.csv in 0.0s
$ cat out.csv
position,subject
0,zero
1,one
2,two
3,three
```

<!-- Source: ran the built binary; crates/mboxturbo-cli/tests/export.rs (csv_writes_a_header_and_a_row_per_message) and tests/progress.rs (the_first_export_prints_the_rebuild_note_and_the_summary_line). -->

Running it again without `--overwrite` fails:

```console
$ mboxturbo export mail.mbox --format csv --columns position,subject -o out.csv
mboxturbo: export target out.csv already exists
$ echo $?
73
```

<!-- Source: ran the built binary; crates/mboxturbo-cli/tests/export.rs (an_existing_output_is_refused_and_left_unchanged). -->

### `info`

```text
mboxturbo info [OPTIONS] <MAILBOX>
```

<!-- Source: ./target/debug/mboxturbo info --help -->

Prints the message count, the earliest and latest dates, and the number of undated messages. It reads the index, so it does not parse the messages. `earliest` and `latest` are left out when no message has a date. Flags: `--index <PATH>`, plus the global flags.

```console
$ mboxturbo info mail.mbox
mboxturbo: index rebuilt
messages: 4
undated: 4
```

<!-- Source: ran the built binary; crates/mboxturbo-cli/tests/show_info.rs (info_of_an_undated_mailbox_prints_no_span). -->

A mailbox with dated messages also prints the span:

```text
messages: 4
earliest: 2024-01-01T00:00:00Z
latest: 2024-03-05T12:30:15Z
undated: 2
```

<!-- Source: crates/mboxturbo-cli/tests/show_info.rs (info_reports_the_count_the_span_and_the_undated_messages). -->

### `show`

```text
mboxturbo show [OPTIONS] <MAILBOX> <POSITION>
```

<!-- Source: ./target/debug/mboxturbo show --help -->

Writes one message's stored bytes to standard output, `From ` separator line included. `<POSITION>` is 0-based. A position at or past the message count exits 64. Flags: `--index <PATH>`, plus the global flags. `--json` cannot be combined with `show`, because standard output carries the message. It exits 64 with one `error` event and no message bytes.

```console
$ mboxturbo show mail.mbox 1
From b@example.com Mon Jan  1 00:00:00 2024
Subject: one
From: b@example.com

body one

$ mboxturbo show mail.mbox 9
mboxturbo: message position 9 is out of range for a mailbox of 4 messages
```

<!-- Source: ran the built binary; crates/mboxturbo-cli/tests/show_info.rs (show_writes_the_stored_bytes_of_the_first_a_middle_and_the_last_message, show_past_the_end_exits_64_naming_the_position) and tests/json.rs (show_with_json_ends_in_an_error_event_and_writes_no_message). -->

## Selection

`--select` takes a comma-separated list of specs, and may be given more than once. A spec is one of:

- `N`, a 0-based position.
- `A..B`, a half-open range: `A` is included and `B` is not.

`--select-file` reads one spec list per line. Blank lines are ignored. A file with no specs exits 64.

All sources are united. The result is sorted and has no duplicates, so `--select 2..4 --select 1..3,2` selects 1, 2 and 3. A malformed spec exits 64 and names the spec. A position at or past the last message exits 64.

```console
$ mboxturbo export mail.mbox --format jsonl --columns position,subject --select 0,2 -o -
{"position":0,"subject":"zero"}
{"position":2,"subject":"two"}
exported 2 messages, 63 bytes to - in 0.0s
```

<!-- Source: ran the built binary; crates/mboxturbo-cli/tests/export.rs (select_ranges_and_positions_are_united_without_duplicates, select_file_lines_are_specs_and_blank_lines_are_ignored, select_and_select_file_are_united). -->

## Date bounds

`--since` keeps messages dated at or after a moment and `--until` keeps messages dated before it, so `--since` is inclusive and `--until` is exclusive. Either may be given alone. Each takes a date `YYYY-MM-DD`, which is midnight UTC, or an RFC 3339 timestamp such as `2024-01-04T12:00:00+02:00`. An offset is compared as the instant it names. A fraction of a second rounds the bound up to the next whole second. A value that is neither exits 64 and names the flag and value.

The bounds read the date in the index, so they do not parse the messages. A message with no `Date:` header, or one that does not parse, has no date and is excluded whenever a bound is given. The bounds intersect with `--select` and `--where`.

The summary line on standard error ends with the count of excluded undated messages, and the `summary` event carries it as `excluded_undated`. The count is the undated messages the bounds excluded from the `--select` positions, or from the whole mailbox without `--select`. Neither appears when no bound is given.

```console
$ mboxturbo export mail.mbox --format jsonl --since 2024-01-01 --columns position -o -
exported 0 messages, 0 bytes to - in 0.0s (4 undated excluded)
```

<!-- Source: ran the built binary on an undated mailbox; crates/mboxturbo-cli/tests/dates.rs (since_is_inclusive_to_the_second_and_until_exclusive, a_plain_date_is_midnight_utc, the_summary_line_says_how_many_undated_messages_were_excluded, the_summary_event_counts_the_undated_messages_a_bound_excluded). -->

## Predicates

`--where` takes a predicate in its JSON form: an object with an `op`, such as `contains` or `equals` on a `header`, and the combinators `and` and `or`, whose `args` must not be empty. `--where-file` reads the same JSON from a file, and the two flags conflict. A predicate that is not JSON or is not valid exits 64 and names the operator at fault. A `--where-file` that cannot be read exits 74 and names the file.

```console
$ mboxturbo export mail.mbox --format jsonl --columns position,subject \
    --where '{"op":"contains","header":"subject","value":"o"}' -o -
```

This keeps the messages whose subject contains an `o`. A predicate intersects with `--select`, `--since` and `--until`. It matches the same messages as the Python package's `header('subject').contains('o')`.

```console
$ mboxturbo export mail.mbox --format jsonl --where '{"op":"and","args":[]}' -o -
mboxturbo: invalid predicate at `and`: an `and` or `or` needs at least one argument
$ echo $?
64
```

<!-- Source: crates/mboxturbo-cli/tests/predicates.rs (a_header_predicate_keeps_the_matching_messages_as_the_python_select_does, a_predicate_intersects_with_select_and_since_as_the_python_select_does, an_invalid_predicate_exits_64_with_an_error_event, an_unreadable_where_file_exits_74_naming_it); the invalid predicate output is from the built binary. -->

## Formats and columns

| Format | Encoding | Columns | Standard output |
|--------|----------|---------|-----------------|
| `arrow` | Arrow IPC stream: a schema message, one record batch per exported batch, an end marker. | `--columns` or the defaults | yes |
| `csv` | RFC 4180, header row, CRLF line ends. List and struct columns are one compact JSON-encoded cell. Dates are RFC 3339 UTC. A missing value is an empty cell. Text cells that look like formulas get a leading apostrophe. | `--columns` or the defaults | yes |
| `eml` | One `.eml` file per message in a directory, named by zero-padded position, plus `manifest.jsonl`. The file holds the stored bytes without the `From ` line, with mboxrd quoting removed. | fixed | no |
| `jsonl` | One JSON object per line, keyed by column name. Structs are JSON objects. Raw bytes are base64. Dates are RFC 3339 UTC. A missing value is `null`. | `--columns` or the defaults | yes |
| `mbox` | The selected messages' stored bytes, `From ` line included, so the output is a mailbox. | fixed | yes |
| `parquet` | One Parquet file with the Arrow schema embedded. | `--columns` or the defaults | no |

`eml` and `mbox` write whole messages, so their columns are fixed: `eml` extracts `raw`, `position`, `message_id` and `date`, and `mbox` extracts `raw`. Passing `--columns` with either exits 64.

```console
$ mboxturbo export mail.mbox --format eml --columns raw -o eml
mboxturbo: --columns cannot be used with Eml, which writes whole messages
```

<!-- Source: ran the built binary; crates/mboxturbo-cli/tests/export.rs (columns_with_eml_or_mbox_exit_64). -->

`parquet` and `eml` cannot go to standard output, and `-o -` with either exits 64 with nothing written.

<!-- Source: crates/mboxturbo-cli/tests/export.rs (parquet_and_eml_cannot_go_to_stdout, csv_to_stdout_writes_only_the_export, jsonl_and_mbox_stream_to_stdout). -->

### Column names

`position`, `offset`, `size`, `raw`, `from`, `to`, `cc`, `reply_to`, `subject`, `date`, `date_offset_minutes`, `message_id`, `received`, `authentication_results`, `received_spf`, `dkim_signature`, `return_path`, `text`, `html`, `attachment_names`, `attachment_types`, `attachment_sizes`, `attachment_sha256`, the structured columns below, and `header:<Name>` for any header.

The defaults are every column that needs no body parsing, except `raw`, which is opt-in. `raw` can be written as `arrow`, `jsonl` and `parquet`, but the `csv` sink refuses it. An unknown column name exits 64 and names the column.

<!-- Source: crates/mboxturbo/src/columns.rs (NAMED, defaults) and crates/mboxturbo/src/csv_sink.rs (is_encodable); crates/mboxturbo-cli/tests/export.rs (an_unknown_column_exits_64_naming_it). -->

### Structured columns

`auth_results`, `arc_sets`, `dkim_signatures`, `received_hops`, `received_spf_parsed` and `microsoft_antispam` parse a header family into structs. They are opt-in. `verdict_dmarc`, `verdict_spf`, `verdict_dkim` and `verdict_compauth` are opt-in text columns.

In JSONL a struct is a JSON object keyed by field name, in alphabetical order, and a list of structs is an array of objects. A missing field is `null`, a boolean is `true` or `false`, and integers are numbers. A message without the header has an empty array, or for `received_hops` and `arc_sets` an object with an empty `hops` or `sets` array. In CSV the same value is one compact JSON text cell, quoted as CSV requires. A message with no value in a column has an empty cell.

```console
$ mboxturbo export mail.mbox --format jsonl --columns position,auth_results -o -
{"position":0,"auth_results":[{"authserv_id":"mx.example.org","entries":[{"method":"dmarc","properties":[{"property":"from","ptype":"header","value":"example.org"}],"reason":null,"result":"pass"}],"issues":[],"trusted":null,"version":null}]}
$ mboxturbo export mail.mbox --format csv --columns position,auth_results -o -
position,auth_results
0,"[{""authserv_id"":""mx.example.org"",""entries"":[{""method"":""dmarc"",""properties"":[{""property"":""from"",""ptype"":""header"",""value"":""example.org""}],""reason"":null,""result"":""pass""}],""issues"":[],""trusted"":null,""version"":null}]"
```

<!-- Source: ran the built binary on a message with one Authentication-Results header; crates/mboxturbo-cli/tests/structured.rs (jsonl_writes_the_structured_columns_as_objects, csv_writes_each_structured_column_as_one_json_cell) and the unit tests in crates/mboxturbo/src/jsonl_sink.rs and csv_sink.rs. -->

The CLI takes no trust set in this version. `trusted` inside `auth_results` and `arc_sets`, `first_external` inside `received_hops`, and every `verdict_*` column are therefore null. To get verdicts, use the Python package and its `Trust`.

```console
$ mboxturbo export mail.mbox --format jsonl --columns position,verdict_dmarc -o -
{"position":0,"verdict_dmarc":null}
```

<!-- Source: ran the built binary; crates/mboxturbo-cli/tests/structured.rs (verdict_columns_are_null_without_a_trust_set). -->

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success, including `--help` and `--version`. |
| 1 | Any other failure. |
| 64 | Usage error: bad arguments, a message position past the last message, or a `--where` or `--where-file` predicate that is not valid. |
| 65 | Corrupt or stale index. |
| 66 | The mailbox does not exist. |
| 73 | The export target exists and `--overwrite` was not given, or `--overwrite` may not replace it: it is of the other kind (file or directory) or a directory with no `manifest.jsonl` that is not empty. |
| 74 | Any other I/O error, including a path not found after the mailbox is open, such as a missing output directory. |
| 129 | Interrupted by SIGHUP. |
| 130 | Interrupted by SIGINT (Ctrl-C), or cancelled with no signal. |
| 143 | Interrupted by SIGTERM. |

<!-- Source: crates/mboxturbo-cli/src/main.rs (module docs) and crates/mboxturbo-cli/src/exit.rs; tests in crates/mboxturbo-cli/tests/export.rs, show_info.rs and json.rs. -->

```console
$ mboxturbo info nope.mbox
mboxturbo: I/O error on nope.mbox: No such file or directory (os error 2)
$ echo $?
66
```

<!-- Source: ran the built binary; crates/mboxturbo-cli/tests/show_info.rs (info_of_a_missing_mailbox_exits_66). -->

On failure the line on standard error starts with `mboxturbo: `.

## JSON events

`--json` writes one JSON object per line on standard output. Every object has `"v": 1` and an `"event"` kind. Keys appear in alphabetical order. The schema is [`schema/events-v1.json`](schema/events-v1.json) in this directory.

`--json` with `-o -` exits 64, because standard output carries the events.

For a successful export the order is `start`, `index`, one or more `progress`, `file`, `summary`. A failure after `start` ends the stream with an `error` event. `info` writes one `info` event.

<!-- Source: crates/mboxturbo-cli/schema/events-v1.json; crates/mboxturbo-cli/tests/json.rs (every_format_writes_a_valid_ordered_stream_ending_in_a_summary). -->

### `start`

The export is about to run. `selected` counts the selected messages.

```json
{"command":"export","event":"start","format":"jsonl","mailbox":"mail.mbox","output":"o.jsonl","selected":2,"v":1}
```

<!-- Source: ran the built binary with --json export --select 1..3; crates/mboxturbo-cli/tests/json.rs (start_counts_only_the_selected_messages). -->

### `index`

Whether opening the mailbox loaded its index (`loaded`) or rebuilt it (`rebuilt`).

```json
{"event":"index","origin":"loaded","v":1}
```

<!-- Source: ran the built binary; crates/mboxturbo-cli/tests/json.rs (the_index_event_says_rebuilt_then_loaded). -->

### `progress`

At most one per second while writing, then one last event where `messages` equals `total`.

```json
{"bytes":529,"event":"progress","messages":2,"total":2,"v":1}
```

<!-- Source: ran the built binary; crates/mboxturbo-cli/tests/json.rs. -->

### `file`

One output path: the file, or the directory of an `eml` export.

```json
{"bytes":529,"event":"file","format":"jsonl","messages":2,"path":"o.jsonl","v":1}
```

<!-- Source: ran the built binary; crates/mboxturbo-cli/tests/json.rs (an_eml_export_emits_one_file_event_for_its_directory). -->

### `summary`

The export finished. It is the last line of a successful run.

```json
{"bytes":529,"elapsed_ms":2,"event":"summary","messages":2,"path":"o.jsonl","v":1}
```

<!-- Source: ran the built binary; crates/mboxturbo-cli/tests/json.rs. -->

### `info`

The output of `mboxturbo info`. `earliest` and `latest` are RFC 3339 UTC strings, or `null` when no message has a date.

```json
{"count":4,"earliest":null,"event":"info","latest":null,"undated":4,"v":1}
```

<!-- Source: ran the built binary; crates/mboxturbo-cli/tests/json.rs (info_writes_one_info_event_valid_against_the_schema, info_of_a_dated_mailbox_writes_its_span_as_strings_valid_against_the_schema). -->

### `error`

The run failed. It is the last line of a failed run. `code` is the process exit code and `message` is the line written to standard error.

```json
{"code":64,"event":"error","message":"mboxturbo: unknown column `bogus`","v":1}
```

<!-- Source: ran the built binary with --json export --columns bogus; crates/mboxturbo-cli/tests/json.rs (a_usage_error_before_the_mailbox_opens_is_only_an_error_event). -->

### Stream rules

- A run that fails before the export starts, such as a usage error or a missing mailbox, writes no `start` event. The stream is the one `error` event.
- `--json` silences all feedback on standard error: no bar, no note and no summary line. Standard error holds only error lines, the same line that the `error` event carries.
- Standard output carries only events, never message data.

<!-- Source: crates/mboxturbo-cli/tests/json.rs (a_usage_error_before_the_mailbox_opens_is_only_an_error_event, a_missing_mailbox_ends_in_an_error_event_with_code_66, without_json_standard_output_carries_no_events) and tests/progress.rs (a_json_export_leaves_stderr_empty_even_when_styling_is_forced, quiet_still_prints_error_lines). -->

## Signals

SIGINT, SIGTERM and SIGHUP cancel a running export. The export stops within one batch and removes what it staged, so nothing is left at the target. The exit code names the signal:

| Signal | Exit code |
|--------|-----------|
| SIGHUP | 129 |
| SIGINT | 130 |
| SIGTERM | 143 |

A text run prints one line on standard error that says the export was interrupted. A `--json` run ends its stream with an `error` event carrying the same code.

A second signal exits at once with that signal's code. It does not wait for the export to stop, and it may leave a staging file beside the target. It exists so that a stuck export never needs `kill -9`.

On Windows, Ctrl-C and Ctrl-Break both exit 130. SIGTERM is not delivered from console events.

<!-- Source: crates/mboxturbo-cli/tests/signals.rs (sigint_cancels_an_export_and_exits_130, sigterm_cancels_an_export_and_exits_143, sighup_cancels_an_export_and_exits_129, a_text_run_prints_one_interrupted_line_and_leaves_nothing, a_second_signal_ends_a_stuck_export_at_once), crates/mboxturbo-cli/tests/console_signals.rs (ctrl_break_cancels_an_export_and_exits_130, Windows only) and crates/mboxturbo-cli/src/signals.rs. -->
