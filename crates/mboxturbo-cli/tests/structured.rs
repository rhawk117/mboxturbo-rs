//! `mboxturbo export` writes the structured header columns as JSON objects in JSONL and as one
//! compact JSON cell in CSV, with the verdict columns null because the CLI takes no trust set.

#[cfg(test)]
mod structured {
    use std::fs;
    use std::process::Command;

    use serde_json::Value;
    use tempfile::TempDir;

    const MAILBOX: &str = concat!(
        "From a@example.com Mon Jan  1 00:00:00 2024\n",
        "Authentication-Results: mx.example.org; dmarc=pass header.from=example.org\n",
        "Received: from relay.example.org by mx.example.net with ESMTP; ",
        "Mon, 1 Jan 2024 00:01:00 +0000\n",
        "Received: from origin.example.com by relay.example.org with SMTP; ",
        "Mon, 1 Jan 2024 00:00:00 +0000\n",
        "Subject: with headers\n\nbody\n\n",
        "From b@example.com Mon Jan  1 00:00:00 2024\n",
        "Subject: without headers\n\nbody\n\n",
    );

    /// Exports the mailbox in `format` with `columns` and returns the text written.
    fn export(format: &str, columns: &str) -> String {
        let dir = TempDir::new().expect("a temporary directory is created");
        let mbox = dir.path().join("mail.mbox");
        fs::write(&mbox, MAILBOX).expect("the fixture mailbox is written");
        let target = dir.path().join(format!("out.{format}"));
        let output = Command::new(env!("CARGO_BIN_EXE_mboxturbo"))
            .args(["export", "--format", format, "--columns", columns, "-o"])
            .arg(&target)
            .arg(&mbox)
            .env("NO_COLOR", "1")
            .output()
            .expect("the built mboxturbo binary runs");
        assert!(
            output.status.success(),
            "the export succeeds: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        fs::read_to_string(target).expect("the export wrote its output")
    }

    /// The fields of one CSV record, with quoted fields unquoted.
    fn split_csv_record(record: &str) -> Vec<String> {
        let mut fields = vec![String::new()];
        let mut quoted = false;
        let mut chars = record.chars().peekable();
        while let Some(ch) = chars.next() {
            let field = fields.last_mut().expect("a field is always open");
            match (ch, quoted) {
                ('"', true) if chars.peek() == Some(&'"') => {
                    field.push('"');
                    let _skipped = chars.next();
                },
                ('"', _) => quoted = !quoted,
                (',', false) => fields.push(String::new()),
                _ => field.push(ch),
            }
        }
        fields
    }

    /// Asserts the parsed authentication results of the first message.
    fn assert_auth(auth: &Value) {
        assert_eq!(
            auth[0]["authserv_id"], "mx.example.org",
            "the authserv-id is the first token of the header"
        );
        assert_eq!(
            auth[0]["entries"][0]["method"], "dmarc",
            "the first entry names its method"
        );
        assert_eq!(
            auth[0]["entries"][0]["result"], "pass",
            "the first entry carries its result"
        );
        assert_eq!(
            auth[0]["trusted"],
            Value::Null,
            "no trust set leaves trusted null"
        );
    }

    /// Asserts the parsed hop chain of the first message.
    fn assert_hops(hops: &Value) {
        let chain = &hops["hops"];
        assert_eq!(
            chain[0]["from_host"], "origin.example.com",
            "the oldest hop comes first"
        );
        assert_eq!(
            chain[0]["by_host"], "relay.example.org",
            "the first hop was received by the relay"
        );
        assert_eq!(
            chain[1]["from_host"], "relay.example.org",
            "the second hop came from the relay"
        );
        assert_eq!(
            chain[1]["by_host"], "mx.example.net",
            "the second hop was received by the mailbox host"
        );
    }

    #[test]
    fn jsonl_writes_the_structured_columns_as_objects() {
        let text = export("jsonl", "position,auth_results,received_hops");
        let rows: Vec<Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).expect("a row is JSON"))
            .collect();
        assert_eq!(rows.len(), 2, "one row per message");
        assert_auth(&rows[0]["auth_results"]);
        assert_hops(&rows[0]["received_hops"]);
        assert_eq!(
            rows[1]["auth_results"],
            Value::Array(Vec::new()),
            "a message without the header has an empty list"
        );
        assert_eq!(
            rows[1]["received_hops"]["hops"],
            Value::Array(Vec::new()),
            "a message without hops has an empty chain"
        );
    }

    #[test]
    fn csv_writes_each_structured_column_as_one_json_cell() {
        let text = export("csv", "position,auth_results,received_hops");
        let records: Vec<&str> = text.split("\r\n").collect();
        let first = split_csv_record(records[1]);
        assert_eq!(first.len(), 3, "one cell per column: {first:?}");
        let auth: Value = serde_json::from_str(&first[1]).expect("the cell is JSON");
        let hops: Value = serde_json::from_str(&first[2]).expect("the cell is JSON");
        assert_auth(&auth);
        assert_hops(&hops);
    }

    #[test]
    fn verdict_columns_are_null_without_a_trust_set() {
        let columns = "position,verdict_dmarc,verdict_spf,verdict_dkim,verdict_compauth";
        let text = export("jsonl", columns);
        for line in text.lines() {
            let row: Value = serde_json::from_str(line).expect("a row is JSON");
            for column in &columns.split(',').collect::<Vec<_>>()[1..] {
                assert_eq!(
                    row[column],
                    Value::Null,
                    "the CLI has no trust set, so `{column}` is null"
                );
            }
        }
    }
}
