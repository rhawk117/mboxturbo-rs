# mboxturbo-headers

Total, panic-free parsers for email header values.

Each parser takes the bytes of one header value and returns the best value it could recover
together with the issues found on the way. Malformed input is never a panic and never an
error: it is an issue carrying the byte offset where the problem starts. Input past a cap,
such as the maximum header size, is truncated or skipped and reported as an issue too.

Parsers cover `Date`, `Received`, `Authentication-Results`, `ARC-*`, `DKIM-Signature`,
`Received-SPF`, `X-Microsoft-Antispam` and RFC 2047 encoded words.

The crate is the parsing layer of [mboxturbo](https://github.com/rhawk117/mboxturbo), which
reads mbox files into Arrow and Parquet.

## License

Apache-2.0.
