//! `DateBounds` admits a date exactly when it is at or after `since` and before `until`.

#[cfg(test)]
mod date_bounds {
    use mboxturbo::DateBounds;

    #[test]
    fn open_bounds_admit_every_date_and_report_unbounded() {
        let bounds = DateBounds::new(None, None);
        assert!(
            bounds.is_unbounded(),
            "no bound on either side is unbounded"
        );
        assert_eq!(
            bounds,
            DateBounds::default(),
            "the default is the open window"
        );
        for date in [i64::MIN, -1, 0, 1, i64::MAX] {
            assert!(bounds.admits(date), "open bounds admit {date}");
        }
    }

    #[test]
    fn since_is_inclusive_and_leaves_the_top_open() {
        let bounds = DateBounds::new(Some(100), None);
        assert!(!bounds.is_unbounded(), "a since bound is bounded");
        assert!(!bounds.admits(99), "a date before since is refused");
        assert!(bounds.admits(100), "since itself is admitted");
        assert!(bounds.admits(i64::MAX), "nothing caps the top");
    }

    #[test]
    fn until_is_exclusive_and_leaves_the_bottom_open() {
        let bounds = DateBounds::new(None, Some(200));
        assert!(!bounds.is_unbounded(), "an until bound is bounded");
        assert!(bounds.admits(i64::MIN), "nothing caps the bottom");
        assert!(bounds.admits(199), "a date before until is admitted");
        assert!(!bounds.admits(200), "until itself is refused");
    }

    #[test]
    fn closed_bounds_admit_the_half_open_interval() {
        let bounds = DateBounds::new(Some(100), Some(200));
        assert!(!bounds.admits(99), "below since is refused");
        assert!(bounds.admits(100), "since is admitted");
        assert!(bounds.admits(199), "just below until is admitted");
        assert!(!bounds.admits(200), "until is refused");
    }

    #[test]
    fn an_empty_window_admits_nothing() {
        let bounds = DateBounds::new(Some(200), Some(200));
        assert!(!bounds.admits(200), "since equal to until leaves no date");
        assert!(!bounds.admits(199), "below an empty window is refused");
    }
}
