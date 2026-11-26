//! Staged destinations appear at the target only when committed, refuse to clobber unless told
//! to, and leave nothing behind when dropped.

#[cfg(test)]
mod staging {
    use std::fs;
    use std::fs::File;
    use std::path::Path;

    use mboxturbo::{Destination, MboxTurboError, Overwrite};
    use tempfile::TempDir;

    fn entries(directory: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(directory)
            .expect("parent directory is readable")
            .map(|entry| {
                entry
                    .expect("directory entry is readable")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_staged_file_sits_in_the_parent_and_appears_only_on_commit() {
        let parent = TempDir::new().expect("parent creates");
        let target = parent.path().join("out.parquet");
        let mut staged = Destination::File(target.clone())
            .stage(Overwrite::Refuse)
            .expect("stages");
        staged
            .writer()
            .expect("a file has a writer")
            .write_all(b"data")
            .expect("writes");
        assert!(!target.exists(), "nothing at the target before commit");
        assert_eq!(
            entries(parent.path()).len(),
            1,
            "one staged file in the parent"
        );
        let committed = staged.commit().expect("commits");
        assert_eq!(committed, Some(target.clone()), "commit returns the target");
        assert_eq!(
            fs::read(&target).expect("target reads"),
            b"data",
            "content is committed"
        );
        assert_eq!(
            entries(parent.path()),
            ["out.parquet"],
            "no staged leftovers"
        );
    }

    #[test]
    fn dropping_a_staged_file_leaves_nothing() {
        let parent = TempDir::new().expect("parent creates");
        let target = parent.path().join("out.parquet");
        let mut staged = Destination::File(target)
            .stage(Overwrite::Refuse)
            .expect("stages");
        staged
            .writer()
            .expect("a file has a writer")
            .write_all(b"data")
            .expect("writes");
        drop(staged);
        assert!(
            entries(parent.path()).is_empty(),
            "drop removes the staged file"
        );
    }

    #[test]
    fn a_staged_directory_appears_only_on_commit() {
        let parent = TempDir::new().expect("parent creates");
        let target = parent.path().join("out");
        let staged = Destination::Directory(target.clone())
            .stage(Overwrite::Refuse)
            .expect("stages");
        let inner = staged
            .directory()
            .expect("a directory has a path")
            .join("a.eml");
        assert_eq!(
            inner.parent().and_then(Path::parent),
            Some(parent.path()),
            "staged in parent"
        );
        fs::write(&inner, b"x").expect("fills staging directory");
        assert!(!target.exists(), "nothing at the target before commit");
        drop(staged.commit().expect("commits"));
        assert_eq!(
            fs::read(target.join("a.eml")).expect("file moved"),
            b"x",
            "contents move"
        );
        assert_eq!(entries(parent.path()), ["out"], "no staged leftovers");
    }

    #[test]
    fn a_failed_directory_replacement_keeps_the_previous_output() {
        let parent = TempDir::new().expect("parent creates");
        let target = parent.path().join("out");
        fs::create_dir_all(&target).expect("previous output creates");
        fs::write(target.join("old.eml"), b"old").expect("previous output fills");
        let staged = Destination::Directory(target.clone())
            .stage(Overwrite::Replace)
            .expect("stages");
        let staging = staged.directory().expect("a directory has a path");
        fs::write(staging.join("new.eml"), b"new").expect("fills staging directory");
        // FC-1: removing the staged directory makes the second rename fail.
        fs::remove_dir_all(staging).expect("staging directory is removed");
        let error = staged.commit().expect_err("the rename cannot succeed");
        assert!(
            matches!(&error, MboxTurboError::Io { path, .. } if path == &target),
            "the error names the target",
        );
        assert_eq!(
            fs::read(target.join("old.eml")).expect("previous output survives"),
            b"old",
            "the previous output is back at the target"
        );
        assert_eq!(
            entries(parent.path()),
            ["out"],
            "no staged or set-aside leftovers"
        );
    }

    #[test]
    fn a_replaced_directory_leaves_only_the_new_output() {
        let parent = TempDir::new().expect("parent creates");
        let target = parent.path().join("out");
        fs::create_dir_all(&target).expect("previous output creates");
        fs::write(target.join("old.eml"), b"old").expect("previous output fills");
        let staged = Destination::Directory(target.clone())
            .stage(Overwrite::Replace)
            .expect("stages");
        let staging = staged.directory().expect("a directory has a path");
        fs::write(staging.join("new.eml"), b"new").expect("fills staging directory");
        drop(staged.commit().expect("commits"));
        assert_eq!(entries(&target), ["new.eml"], "only the new output remains");
        assert_eq!(
            entries(parent.path()),
            ["out"],
            "no leftovers in the parent"
        );
    }

    #[test]
    fn dropping_a_staged_directory_leaves_nothing() {
        let parent = TempDir::new().expect("parent creates");
        let other = Destination::Directory(parent.path().join("gone"))
            .stage(Overwrite::Refuse)
            .expect("stages");
        drop(other);
        assert!(
            entries(parent.path()).is_empty(),
            "drop removes the staged directory"
        );
    }

    #[test]
    fn an_existing_target_is_refused_before_anything_is_created() {
        let parent = TempDir::new().expect("parent creates");
        let target = parent.path().join("out");
        fs::write(&target, b"old").expect("existing target");
        for destination in [
            Destination::File(target.clone()),
            Destination::Directory(target.clone()),
        ] {
            let error = destination
                .stage(Overwrite::Refuse)
                .expect_err("existing target is refused");
            assert!(
                matches!(&error, MboxTurboError::TargetExists { path } if *path == target),
                "the error names the target",
            );
        }
        assert_eq!(entries(parent.path()), ["out"], "nothing was staged");
        assert_eq!(
            fs::read(&target).expect("reads"),
            b"old",
            "target untouched"
        );
    }

    #[test]
    fn overwrite_replaces_an_existing_file_on_commit() {
        let parent = TempDir::new().expect("parent creates");
        let target = parent.path().join("out");
        fs::write(&target, b"old").expect("existing target");
        let mut staged = Destination::File(target.clone())
            .stage(Overwrite::Replace)
            .expect("stages");
        staged
            .writer()
            .expect("a file has a writer")
            .write_all(b"new")
            .expect("writes");
        drop(staged.commit().expect("commits"));
        assert_eq!(fs::read(&target).expect("reads"), b"new", "file replaced");
    }

    #[test]
    fn overwrite_replaces_an_existing_directory_on_commit() {
        let parent = TempDir::new().expect("parent creates");
        let target = parent.path().join("out");
        fs::create_dir_all(&target).expect("existing directory");
        fs::write(target.join("old.eml"), b"old").expect("old content");
        let staged = Destination::Directory(target.clone())
            .stage(Overwrite::Replace)
            .expect("stages");
        fs::write(staged.directory().expect("path").join("new.eml"), b"new").expect("fills");
        drop(staged.commit().expect("commits"));
        assert_eq!(entries(&target), ["new.eml"], "old contents are gone");
    }

    #[test]
    fn a_stream_is_written_directly_with_no_staging_or_path() {
        let parent = TempDir::new().expect("parent creates");
        let sink = parent.path().join("sink");
        let writer = File::create(&sink).expect("sink creates");
        let mut staged = Destination::Stream(Box::new(writer))
            .stage(Overwrite::Refuse)
            .expect("a stream always stages");
        staged
            .writer()
            .expect("a stream has a writer")
            .write_all(b"hello")
            .expect("writes");
        assert_eq!(
            fs::read(&sink).expect("sink reads"),
            b"hello",
            "bytes arrive before commit"
        );
        assert_eq!(
            staged.commit().expect("commits"),
            None,
            "a stream has no final path"
        );
    }

    #[test]
    fn cancelled_carries_the_target_and_the_count() {
        let error = MboxTurboError::Cancelled {
            target: None,
            written: 7,
        };
        assert!(
            matches!(
                error,
                MboxTurboError::Cancelled {
                    target: None,
                    written: 7
                }
            ),
            "a stream cancellation reports no path and the count",
        );
    }
}
