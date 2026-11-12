//! The synthetic mbox generator is deterministic, matches its size and date mix, and produces
//! files `Mailbox` indexes to exactly the generated message count.

mod common;

#[cfg(test)]
mod fixture {
    use std::path::PathBuf;
    use std::{fs, ptr};

    use mboxturbo::Mailbox;
    use rayon::iter::ParallelIterator as _;
    use tempfile::TempDir;

    use crate::common::{Spec, Summary, file_name, generate};

    fn generated(spec: &Spec) -> (TempDir, PathBuf, Summary) {
        let directory = tempfile::tempdir().expect("temporary directory is created");
        let path = directory.path().join(file_name(spec));
        let summary = generate(&path, spec).expect("the generator writes the fixture");
        (directory, path, summary)
    }

    fn dated_count(mailbox: &Mailbox) -> usize {
        (0..mailbox.len())
            .filter(|&position| {
                mailbox
                    .message(position)
                    .expect("position is within the mailbox")
                    .date()
                    .is_some()
            })
            .count()
    }

    #[test]
    fn iteration_yields_each_message_of_the_fixture_in_both_directions_and_in_parallel() {
        let (_directory, path, _) = generated(&Spec::default());
        let mailbox = Mailbox::open(path).expect("the fixture opens");
        let forward: Vec<&[u8]> = mailbox.iter().collect();
        assert_eq!(forward.len(), mailbox.len(), "one item per message");
        for (position, item) in forward.iter().enumerate() {
            let raw = mailbox.raw(position).expect("the position exists");
            assert!(
                ptr::eq(item.as_ptr(), raw.as_ptr()) && item.len() == raw.len(),
                "item {position} is the span raw({position}) reports"
            );
        }
        let mut backward: Vec<&[u8]> = mailbox.iter().rev().collect();
        backward.reverse();
        assert_eq!(backward, forward, "reverse iteration visits the same items");
        let parallel: Vec<&[u8]> = mailbox.par_iter().collect();
        assert_eq!(parallel, forward, "par_iter matches iter");
    }

    #[test]
    fn the_same_seed_and_count_give_identical_bytes_and_another_seed_differs() {
        let spec = Spec {
            messages: 300,
            seed: 7,
        };
        let (_first_dir, first, _) = generated(&spec);
        let (_second_dir, second, _) = generated(&spec);
        let (_other_dir, other, _) = generated(&Spec { seed: 8, ..spec });
        let first_bytes = fs::read(first).expect("first fixture is readable");
        assert_eq!(
            first_bytes,
            fs::read(second).expect("second fixture is readable"),
            "equal specs must produce byte-identical files"
        );
        assert_ne!(
            first_bytes,
            fs::read(other).expect("other fixture is readable"),
            "a different seed must change the file"
        );
    }

    #[test]
    fn the_summary_counts_match_the_file_and_what_mailbox_sees() {
        let spec = Spec::default();
        let (_directory, path, summary) = generated(&spec);
        assert_eq!(
            summary.bytes,
            fs::metadata(&path).expect("fixture has metadata").len(),
            "summary byte count equals the file length"
        );
        let mailbox = Mailbox::open(&path).expect("the fixture opens");
        assert_eq!(
            mailbox.len(),
            10_000,
            "scanner count equals generated count"
        );
        assert_eq!(
            summary.messages, 10_000,
            "summary reports the requested count"
        );
        let dated = dated_count(&mailbox);
        assert_eq!(
            u64::try_from(dated).expect("count fits u64"),
            summary.dated,
            "Message::date is Some exactly for the messages the generator dated"
        );
        let undated = summary.messages - summary.dated;
        assert!(
            (50..=200).contains(&undated),
            "about 1% undated, got {undated}"
        );
    }

    #[test]
    fn sizes_are_log_normal_around_ten_kilobytes_with_rare_outliers() {
        let (_directory, path, summary) = generated(&Spec::default());
        let mailbox = Mailbox::open(&path).expect("the fixture opens");
        let mut sizes: Vec<usize> = mailbox.iter().map(<[u8]>::len).collect();
        sizes.sort_unstable();
        let median = sizes[sizes.len() >> 1_u32];
        let mean = summary
            .bytes
            .checked_div(summary.messages)
            .expect("the fixture holds messages");
        assert!(
            (7_000..=9_500).contains(&median),
            "median near 8 KB, got {median}"
        );
        assert!(
            (8_500..=12_500).contains(&mean),
            "mean near 10 KB, got {mean}"
        );
        let outliers = sizes.iter().filter(|&&size| size >= 256 * 1024).count();
        assert!(outliers <= 10, "outliers are rare, got {outliers}");
        assert!(
            sizes.iter().all(|&size| size <= 4 * 1024 * 1024 + 4096),
            "outliers stop at 4 MB"
        );
    }

    #[test]
    fn dates_mostly_increase_across_consecutive_dated_messages() {
        let (_directory, path, _) = generated(&Spec::default());
        let mailbox = Mailbox::open(&path).expect("the fixture opens");
        let dates: Vec<i64> = (0..mailbox.len())
            .filter_map(|position| mailbox.message(position)?.date())
            .map(|stamp| stamp.unix_seconds)
            .collect();
        let ordered = dates
            .windows(2)
            .filter(|pair| matches!(pair, [earlier, later] if earlier <= later))
            .count();
        assert!(
            ordered * 100 >= (dates.len() - 1) * 95,
            "95% of dated pairs are non-decreasing"
        );
        assert!(
            dates
                .windows(2)
                .any(|pair| matches!(pair, [earlier, later] if earlier > later)),
            "jitter reorders some pairs"
        );
    }
}
