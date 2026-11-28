//! Staged destinations appear at the target only when committed, refuse to clobber unless told
//! to, and leave nothing behind when dropped.

#[cfg(test)]
mod staging {
    use std::fs;
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;

    use mboxturbo::{Destination, MboxTurboError, Output, Overwrite, Staged};
    use tempfile::TempDir;

    /// The staged file or stream writer.
    fn staged_writer(staged: &mut Staged) -> &mut (dyn Write + Send) {
        match staged.output() {
            Output::Writer(writer) => writer,
            Output::Directory(_) => panic!("a file or stream is staged"),
        }
    }

    /// The staging directory.
    fn staged_directory(staged: &mut Staged) -> &Path {
        match staged.output() {
            Output::Directory(path) => path,
            Output::Writer(_) => panic!("a directory is staged"),
        }
    }

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
        let parent = TempDir::new().expect("the parent temp directory is created");
        let target = parent.path().join("out.parquet");
        let mut staged = Destination::File(target.clone())
            .stage(Overwrite::Refuse)
            .expect("staging a target succeeds");
        staged_writer(&mut staged)
            .write_all(b"data")
            .expect("writing to the staged file succeeds");
        assert!(!target.exists(), "nothing at the target before commit");
        assert_eq!(
            entries(parent.path()).len(),
            1,
            "one staged file in the parent"
        );
        let committed = staged
            .commit()
            .expect("committing the staged target succeeds");
        assert_eq!(committed, Some(target.clone()), "commit returns the target");
        assert_eq!(
            fs::read(&target).expect("the committed target file is readable"),
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
        let parent = TempDir::new().expect("the parent temp directory is created");
        let target = parent.path().join("out.parquet");
        let mut staged = Destination::File(target)
            .stage(Overwrite::Refuse)
            .expect("staging a target succeeds");
        staged_writer(&mut staged)
            .write_all(b"data")
            .expect("writing to the staged file succeeds");
        drop(staged);
        assert!(
            entries(parent.path()).is_empty(),
            "drop removes the staged file"
        );
    }

    #[test]
    fn a_staged_directory_appears_only_on_commit() {
        let parent = TempDir::new().expect("the parent temp directory is created");
        let target = parent.path().join("out");
        let mut staged = Destination::Directory(target.clone())
            .stage(Overwrite::Refuse)
            .expect("staging a target succeeds");
        let inner = staged_directory(&mut staged).join("a.eml");
        assert_eq!(
            inner.parent().and_then(Path::parent),
            Some(parent.path()),
            "staged in parent"
        );
        fs::write(&inner, b"x").expect("fills staging directory");
        assert!(!target.exists(), "nothing at the target before commit");
        drop(
            staged
                .commit()
                .expect("committing the staged target succeeds"),
        );
        assert_eq!(
            fs::read(target.join("a.eml")).expect("the staged file was moved into place"),
            b"x",
            "contents move"
        );
        assert_eq!(entries(parent.path()), ["out"], "no staged leftovers");
    }

    #[test]
    fn a_failed_directory_replacement_keeps_the_previous_output() {
        let parent = TempDir::new().expect("the parent temp directory is created");
        let target = parent.path().join("out");
        fs::create_dir_all(&target).expect("previous output creates");
        fs::write(target.join("old.eml"), b"old").expect("previous output fills");
        fs::write(target.join("manifest.jsonl"), b"").expect("previous manifest is written");
        let mut staged = Destination::Directory(target.clone())
            .stage(Overwrite::Replace)
            .expect("staging a target succeeds");
        let staging = staged_directory(&mut staged);
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
        let parent = TempDir::new().expect("the parent temp directory is created");
        let target = parent.path().join("out");
        fs::create_dir_all(&target).expect("previous output creates");
        fs::write(target.join("old.eml"), b"old").expect("previous output fills");
        fs::write(target.join("manifest.jsonl"), b"").expect("previous manifest is written");
        let mut staged = Destination::Directory(target.clone())
            .stage(Overwrite::Replace)
            .expect("staging a target succeeds");
        let staging = staged_directory(&mut staged);
        fs::write(staging.join("new.eml"), b"new").expect("fills staging directory");
        drop(
            staged
                .commit()
                .expect("committing the staged target succeeds"),
        );
        assert_eq!(entries(&target), ["new.eml"], "only the new output remains");
        assert_eq!(
            entries(parent.path()),
            ["out"],
            "no leftovers in the parent"
        );
    }

    #[test]
    fn dropping_a_staged_directory_leaves_nothing() {
        let parent = TempDir::new().expect("the parent temp directory is created");
        let other = Destination::Directory(parent.path().join("gone"))
            .stage(Overwrite::Refuse)
            .expect("staging a target succeeds");
        drop(other);
        assert!(
            entries(parent.path()).is_empty(),
            "drop removes the staged directory"
        );
    }

    #[test]
    fn an_existing_target_is_refused_before_anything_is_created() {
        let parent = TempDir::new().expect("the parent temp directory is created");
        let target = parent.path().join("out");
        fs::write(&target, b"old").expect("creating the existing target file succeeds");
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
            fs::read(&target).expect("reading the replaced target succeeds"),
            b"old",
            "target untouched"
        );
    }

    #[test]
    fn overwrite_replaces_an_existing_file_on_commit() {
        let parent = TempDir::new().expect("the parent temp directory is created");
        let target = parent.path().join("out");
        fs::write(&target, b"old").expect("creating the existing target file succeeds");
        let mut staged = Destination::File(target.clone())
            .stage(Overwrite::Replace)
            .expect("staging a target succeeds");
        staged_writer(&mut staged)
            .write_all(b"new")
            .expect("writing to the staged file succeeds");
        drop(
            staged
                .commit()
                .expect("committing the staged target succeeds"),
        );
        assert_eq!(
            fs::read(&target).expect("reading the replaced target succeeds"),
            b"new",
            "file replaced"
        );
    }

    #[test]
    fn overwrite_replaces_an_existing_directory_on_commit() {
        let parent = TempDir::new().expect("the parent temp directory is created");
        let target = parent.path().join("out");
        fs::create_dir_all(&target).expect("creating the existing target directory succeeds");
        fs::write(target.join("old.eml"), b"old")
            .expect("writing the old directory content succeeds");
        fs::write(target.join("manifest.jsonl"), b"")
            .expect("writing the previous manifest succeeds");
        let mut staged = Destination::Directory(target.clone())
            .stage(Overwrite::Replace)
            .expect("staging a target succeeds");
        fs::write(staged_directory(&mut staged).join("new.eml"), b"new")
            .expect("filling the staged directory succeeds");
        drop(
            staged
                .commit()
                .expect("committing the staged target succeeds"),
        );
        assert_eq!(entries(&target), ["new.eml"], "old contents are gone");
    }

    /// Stages `destination` with replacing asked for and returns the refusal reason.
    fn replace_refusal(destination: Destination, target: &Path) -> &'static str {
        let error = destination
            .stage(Overwrite::Replace)
            .expect_err("an unreplaceable target is refused at staging");
        let MboxTurboError::TargetNotReplaceable { path, reason } = error else {
            panic!("expected TargetNotReplaceable, got {error:?}");
        };
        assert_eq!(path, target, "the error names the target");
        reason
    }

    #[test]
    fn replace_refuses_a_directory_where_a_file_goes() {
        let parent = TempDir::new().expect("the parent temp directory is created");
        let target = parent.path().join("out.csv");
        fs::create_dir_all(&target).expect("the directory is created");
        fs::write(target.join("keep.txt"), b"keep").expect("the directory is filled");
        let reason = replace_refusal(Destination::File(target.clone()), &target);
        assert_eq!(
            reason, "a directory where a file goes",
            "the reason names the kind"
        );
        assert_eq!(entries(&target), ["keep.txt"], "the directory is unchanged");
        assert_eq!(
            entries(parent.path()),
            ["out.csv"],
            "nothing is left staged"
        );
    }

    #[test]
    fn replace_refuses_a_file_where_a_directory_goes() {
        let parent = TempDir::new().expect("the parent temp directory is created");
        let target = parent.path().join("out");
        fs::write(&target, b"keep").expect("the file is written");
        let reason = replace_refusal(Destination::Directory(target.clone()), &target);
        assert_eq!(
            reason, "a file where a directory goes",
            "the reason names the kind"
        );
        assert_eq!(
            fs::read(&target).expect("the file is readable"),
            b"keep",
            "unchanged"
        );
    }

    #[test]
    fn replace_refuses_a_non_empty_directory_without_a_manifest() {
        let parent = TempDir::new().expect("the parent temp directory is created");
        let target = parent.path().join("out");
        fs::create_dir_all(&target).expect("the directory is created");
        fs::write(target.join("keep.txt"), b"keep").expect("the directory is filled");
        let reason = replace_refusal(Destination::Directory(target.clone()), &target);
        assert!(
            reason.contains("manifest.jsonl"),
            "the reason names the manifest: {reason}"
        );
        assert_eq!(entries(&target), ["keep.txt"], "the directory is unchanged");
        assert_eq!(
            fs::read(target.join("keep.txt")).expect("the file is readable"),
            b"keep",
            "the file is byte-for-byte unchanged"
        );
    }

    #[test]
    fn replace_refuses_at_commit_a_target_that_became_unreplaceable_after_staging() {
        let parent = TempDir::new().expect("the parent temp directory is created");
        let target = parent.path().join("out");
        let mut staged = Destination::Directory(target.clone())
            .stage(Overwrite::Replace)
            .expect("an absent target stages");
        fs::write(staged_directory(&mut staged).join("new.eml"), b"new")
            .expect("the staged directory is filled");
        fs::create_dir_all(&target).expect("the target appears");
        fs::write(target.join("keep.txt"), b"keep").expect("the target is filled");
        let error = staged.commit().expect_err("the target may not be replaced");
        assert!(
            matches!(error, MboxTurboError::TargetNotReplaceable { .. }),
            "commit refuses the new unrelated directory"
        );
        assert_eq!(entries(&target), ["keep.txt"], "the directory is unchanged");
    }

    #[test]
    fn replace_accepts_an_empty_directory_and_one_holding_a_manifest() {
        let parent = TempDir::new().expect("the parent temp directory is created");
        for (name, manifest) in [("empty", false), ("earlier", true)] {
            let target = parent.path().join(name);
            fs::create_dir_all(&target).expect("the directory is created");
            if manifest {
                fs::write(target.join("manifest.jsonl"), b"").expect("the manifest is written");
                fs::write(target.join("old.eml"), b"old").expect("the old output is written");
            }
            let mut staged = Destination::Directory(target.clone())
                .stage(Overwrite::Replace)
                .expect("a replaceable directory stages");
            fs::write(staged_directory(&mut staged).join("new.eml"), b"new")
                .expect("the staged directory is filled");
            drop(staged.commit().expect("the directory is replaced"));
            assert_eq!(entries(&target), ["new.eml"], "{name} is replaced");
        }
    }

    #[test]
    fn a_stream_is_written_directly_with_no_staging_or_path() {
        let parent = TempDir::new().expect("the parent temp directory is created");
        let sink = parent.path().join("sink");
        let writer = File::create(&sink).expect("the sink file is created");
        let mut staged = Destination::Stream(Box::new(writer))
            .stage(Overwrite::Refuse)
            .expect("a stream always stages");
        staged_writer(&mut staged)
            .write_all(b"hello")
            .expect("writing to the staged file succeeds");
        assert_eq!(
            fs::read(&sink).expect("the sink file is readable"),
            b"hello",
            "bytes arrive before commit"
        );
        assert_eq!(
            staged
                .commit()
                .expect("committing the staged target succeeds"),
            None,
            "a stream has no final path"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_committed_directory_has_the_mode_a_created_directory_gets() {
        use std::os::unix::fs::PermissionsExt as _;

        let parent = TempDir::new().expect("the parent temp directory is created");
        let reference = parent.path().join("reference");
        fs::create_dir_all(&reference).expect("the reference directory is created");
        let target = parent.path().join("out");
        let staged = Destination::Directory(target.clone())
            .stage(Overwrite::Refuse)
            .expect("the directory stages");
        let committed = staged
            .commit()
            .expect("committing the staged directory succeeds");
        assert_eq!(
            committed,
            Some(target.clone()),
            "the directory commits at the target"
        );

        let mode = |path: &Path| {
            fs::metadata(path)
                .expect("the directory has metadata")
                .permissions()
                .mode()
                & 0o7777
        };
        assert_eq!(
            mode(&target),
            mode(&reference),
            "the committed directory must not keep tempfile's private 0700 mode"
        );
    }
}
