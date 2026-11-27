//! Plan invariant I2, timing half: every parser takes time proportional to its input, so
//! eight times the input must never cost twenty times the time (linear is about 8, quadratic
//! about 64).

#[cfg(test)]
mod linearity {
    use std::hint::black_box;
    use std::iter::repeat_with;
    use std::sync::{Mutex, PoisonError};
    use std::time::{Duration, Instant};

    use mboxturbo_headers::{
        ArcHeader, MAX_HEADER_BYTES, TrustSet, decode_encoded_words, parse_arc_sets,
        parse_authentication_results, parse_date, parse_dkim_signature, parse_ms_antispam,
        parse_received_hops, parse_received_spf, parse_tag_list, tokenize,
    };

    const GROWTH: usize = 8;
    const MAX_RATIO: u32 = 20;
    const RUNS: usize = 5;
    const MIN_BASE_TIME: Duration = Duration::from_millis(1);
    const FIRST_BASE: usize = 1 << 10;

    /// Repeating units that stress nesting, quoting, encoded words, entries and invalid bytes.
    const UNITS: [&[u8]; 6] = [
        b"(",
        b"\"\\",
        b"=?utf-8?q?=C3?= ",
        b"; a=b",
        b"\xff\r\n ",
        b"<[a@b.c, ",
    ];

    /// Timings share the machine, so one test at a time runs its measurements.
    static TIMING: Mutex<()> = Mutex::new(());

    fn tokenize_work(input: &[u8]) -> usize {
        tokenize(input).issues().len()
    }

    fn encoded_word_work(input: &[u8]) -> usize {
        decode_encoded_words(input).issues().len()
    }

    fn date_work(input: &[u8]) -> usize {
        parse_date(input).issues().len()
    }

    fn auth_results_work(input: &[u8]) -> usize {
        parse_authentication_results(input, None).issues().len()
    }

    fn trusted_auth_results_work(input: &[u8]) -> usize {
        let mut set = TrustSet::new();
        let _chain = set.add_authserv_id("a");
        parse_authentication_results(input, Some(&set))
            .issues()
            .len()
    }

    fn tag_list_work(input: &[u8]) -> usize {
        parse_tag_list(input).issues().len()
    }

    fn dkim_work(input: &[u8]) -> usize {
        parse_dkim_signature(input).issues().len()
    }

    fn arc_work(input: &[u8]) -> usize {
        parse_arc_sets(&[ArcHeader::Seal(input)], None)
            .issues()
            .len()
    }

    fn received_spf_work(input: &[u8]) -> usize {
        parse_received_spf(input).issues().len()
    }

    fn received_hops_work(input: &[u8]) -> usize {
        parse_received_hops(&[input], None).issues().len()
    }

    fn ms_antispam_work(input: &[u8]) -> usize {
        parse_ms_antispam(input).issues().len()
    }

    fn best_of_runs(parse: fn(&[u8]) -> usize, input: &[u8]) -> Duration {
        repeat_with(|| {
            let started = Instant::now();
            let _issues = black_box(parse(black_box(input)));
            started.elapsed()
        })
        .take(RUNS)
        .min()
        .unwrap_or(Duration::ZERO)
    }

    /// The smallest power-of-two multiple of `FIRST_BASE` whose single run takes `MIN_BASE_TIME`,
    /// stopping where eight times the size would pass the header byte cap.
    fn calibrated_base(parse: fn(&[u8]) -> usize, unit: &[u8]) -> usize {
        let mut base = FIRST_BASE;
        while base.saturating_mul(GROWTH * 2) <= MAX_HEADER_BYTES {
            let started = Instant::now();
            let _issues = black_box(parse(black_box(&unit.repeat(base.div_ceil(unit.len())))));
            if started.elapsed() >= MIN_BASE_TIME {
                break;
            }
            base = base.saturating_mul(2);
        }
        base
    }

    fn assert_linear(parser: &str, parse: fn(&[u8]) -> usize) {
        let _guard = TIMING.lock().unwrap_or_else(PoisonError::into_inner);
        for unit in UNITS {
            let base = calibrated_base(parse, unit);
            let small_input = unit.repeat(base.div_ceil(unit.len()));
            let large_input = unit.repeat(base.saturating_mul(GROWTH).div_ceil(unit.len()));
            let small = best_of_runs(parse, &small_input);
            let large = best_of_runs(parse, &large_input);
            assert!(
                large < small.saturating_mul(MAX_RATIO),
                "{parser} is superlinear on repeated {unit:?}: {} bytes took {small:?} but {} \
                 bytes took {large:?}, more than {MAX_RATIO} times as long",
                small_input.len(),
                large_input.len(),
            );
        }
    }

    #[test]
    fn tokenize_time_grows_linearly_with_input() {
        assert_linear("tokenize", tokenize_work);
    }

    #[test]
    fn decode_encoded_words_time_grows_linearly_with_input() {
        assert_linear("decode_encoded_words", encoded_word_work);
    }

    #[test]
    fn parse_date_time_grows_linearly_with_input() {
        assert_linear("parse_date", date_work);
    }

    #[test]
    fn parse_authentication_results_without_trust_time_grows_linearly_with_input() {
        assert_linear(
            "parse_authentication_results without trust",
            auth_results_work,
        );
    }

    #[test]
    fn parse_authentication_results_with_trust_time_grows_linearly_with_input() {
        assert_linear(
            "parse_authentication_results with trust",
            trusted_auth_results_work,
        );
    }

    #[test]
    fn parse_tag_list_time_grows_linearly_with_input() {
        assert_linear("parse_tag_list", tag_list_work);
    }

    #[test]
    fn parse_dkim_signature_time_grows_linearly_with_input() {
        assert_linear("parse_dkim_signature", dkim_work);
    }

    #[test]
    fn parse_arc_sets_time_grows_linearly_with_input() {
        assert_linear("parse_arc_sets", arc_work);
    }

    #[test]
    fn parse_received_spf_time_grows_linearly_with_input() {
        assert_linear("parse_received_spf", received_spf_work);
    }

    #[test]
    fn parse_received_hops_time_grows_linearly_with_input() {
        assert_linear("parse_received_hops", received_hops_work);
    }

    #[test]
    fn parse_ms_antispam_time_grows_linearly_with_input() {
        assert_linear("parse_ms_antispam", ms_antispam_work);
    }
}
