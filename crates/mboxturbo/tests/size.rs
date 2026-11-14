//! The v2 index stays within its byte budget per message on a generated mailbox.

mod common;

#[cfg(test)]
mod size {
    use mboxturbo::{IndexPolicy, MailboxBuilder};

    use crate::common::{Spec, file_name, generate};

    /// Bytes per message each of the starts and dates sections may take.
    const BUDGET: u64 = 3;

    #[test]
    fn the_starts_and_dates_sections_take_at_most_three_bytes_per_message() {
        let spec = Spec::default();
        let directory = tempfile::tempdir().expect("temporary directory is created");
        let path = directory.path().join(file_name(&spec));
        let _summary = generate(&path, &spec).expect("the generator writes the fixture");
        let mailbox = MailboxBuilder::new()
            .index(IndexPolicy::Memory)
            .open(&path)
            .expect("the fixture opens with an in-memory index");
        let messages = u64::try_from(mailbox.len()).expect("the message count fits in u64");
        let bytes = mailbox.index().bytes();
        assert!(
            bytes.starts <= BUDGET * messages,
            "starts take {} bytes for {messages} messages, over {BUDGET} per message",
            bytes.starts
        );
        assert!(
            bytes.dates <= BUDGET * messages,
            "dates take {} bytes for {messages} messages, over {BUDGET} per message",
            bytes.dates
        );
    }
}
