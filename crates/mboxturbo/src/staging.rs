//! Export destinations staged next to their target and committed atomically.

use std::fmt;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use tempfile::{NamedTempFile, TempDir};

use crate::error::MboxTurboError;

/// Name of the previous output inside its set-aside holder directory.
const SET_ASIDE: &str = "previous";

/// The manifest's file name, as the EML exporter writes it (`MANIFEST` in `eml_sink.rs`).
const MANIFEST: &str = "manifest.jsonl";

/// Where an error about a stream destination says it happened.
const STREAM_LABEL: &str = "<stream>";

/// Where an export goes.
#[non_exhaustive]
pub enum Destination {
    /// A directory of files, written atomically as a whole.
    Directory(PathBuf),
    /// A single file, written atomically.
    File(PathBuf),
    /// A caller-owned writer; nothing is staged and nothing is checked for existence.
    Stream(Box<dyn Write + Send>),
}

/// The kind of place an export writes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DestinationKind {
    /// A directory of files.
    Directory,
    /// A single file.
    File,
    /// A caller-owned writer.
    Stream,
}

impl fmt::Display for DestinationKind {
    #[expect(
        clippy::renamed_function_params,
        reason = "the trait calls it `f`, a one-letter name the min_ident_chars lint bans"
    )]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Directory => "directory",
            Self::File => "file",
            Self::Stream => "stream",
        })
    }
}

/// The destination a sink writes to, by the kind it accepted.
#[expect(
    clippy::exhaustive_enums,
    reason = "a sink matches every output kind and must not need a wildcard arm"
)]
pub enum Output<'staged> {
    /// The staging directory of a directory destination; the sink creates its files inside it.
    Directory(&'staged Path),
    /// The writer of a file or stream destination; the sink writes its bytes to it.
    Writer(&'staged mut (dyn Write + Send)),
}

/// What to do when the export target already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Overwrite {
    /// Fail with [`MboxTurboError::TargetExists`].
    Refuse,
    /// Replace the existing file or directory when the export commits.
    Replace,
}

/// What a finished export produced.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ExportSummary {
    /// Bytes written to the destination.
    pub bytes: u64,
    /// Wall-clock time the export took.
    pub elapsed: Duration,
    /// Messages written.
    pub messages: u64,
    /// The committed file or directory; `None` for a stream.
    pub path: Option<PathBuf>,
}

/// A destination ready to be written: output goes to a hidden staging area in the target's
/// parent directory until [`Staged::commit`] moves it to the target.
///
/// Dropping a `Staged` without committing removes the staged file or directory, leaving the
/// target untouched.
pub struct Staged {
    /// The staging area or stream.
    kind: Kind,
    /// Whether an existing target is replaced on commit.
    overwrite: Overwrite,
    /// The final path; `None` for a stream.
    target: Option<PathBuf>,
}

/// The staging area behind a [`Staged`].
enum Kind {
    /// A staged directory, removed on drop.
    Directory(TempDir),
    /// A staged file, removed on drop.
    File(NamedTempFile),
    /// The caller's writer.
    Stream(Box<dyn Write + Send>),
}

impl fmt::Debug for Destination {
    #[expect(
        clippy::renamed_function_params,
        reason = "the trait calls it `f`, a one-letter name the min_ident_chars lint bans"
    )]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Directory(path) => formatter.debug_tuple("Directory").field(path).finish(),
            Self::File(path) => formatter.debug_tuple("File").field(path).finish(),
            Self::Stream(_) => formatter.debug_tuple("Stream").finish_non_exhaustive(),
        }
    }
}

impl fmt::Debug for Output<'_> {
    #[expect(
        clippy::renamed_function_params,
        reason = "the trait calls it `f`, a one-letter name the min_ident_chars lint bans"
    )]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Directory(path) => formatter.debug_tuple("Directory").field(path).finish(),
            Self::Writer(_) => formatter.debug_tuple("Writer").finish_non_exhaustive(),
        }
    }
}

impl fmt::Debug for Staged {
    #[expect(
        clippy::renamed_function_params,
        reason = "the trait calls it `f`, a one-letter name the min_ident_chars lint bans"
    )]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Staged")
            .field("overwrite", &self.overwrite)
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl Destination {
    /// Which kind of destination this is.
    #[must_use]
    pub const fn kind(&self) -> DestinationKind {
        match self {
            Self::Directory(_) => DestinationKind::Directory,
            Self::File(_) => DestinationKind::File,
            Self::Stream(_) => DestinationKind::Stream,
        }
    }

    /// The path this destination will be committed to; `None` for a stream.
    pub(crate) fn path(&self) -> Option<PathBuf> {
        match self {
            Self::Directory(path) | Self::File(path) => Some(path.clone()),
            Self::Stream(_) => None,
        }
    }

    /// Prepares the destination for writing.
    ///
    /// A file or directory is staged in the target's parent directory, never the system
    /// temporary directory, so that committing is a rename on one filesystem. A stream is
    /// used as given, with no existence check.
    ///
    /// # Errors
    ///
    /// [`MboxTurboError::TargetExists`] when the target exists and `overwrite` is
    /// [`Overwrite::Refuse`]; this is checked before anything is created.
    /// [`MboxTurboError::Io`] when the staging area cannot be created.
    pub fn stage(self, overwrite: Overwrite) -> Result<Staged, MboxTurboError> {
        match self {
            Self::Directory(target) => {
                refuse_existing(&target, overwrite, DestinationKind::Directory)?;
                let directory = staging_directory(parent_of(&target))
                    .map_err(|source| MboxTurboError::io(&target, source))?;
                Ok(Staged {
                    kind: Kind::Directory(directory),
                    overwrite,
                    target: Some(target),
                })
            },
            Self::File(target) => {
                refuse_existing(&target, overwrite, DestinationKind::File)?;
                let file = NamedTempFile::new_in(parent_of(&target))
                    .map_err(|source| MboxTurboError::io(&target, source))?;
                Ok(Staged {
                    kind: Kind::File(file),
                    overwrite,
                    target: Some(target),
                })
            },
            Self::Stream(writer) => Ok(Staged {
                kind: Kind::Stream(writer),
                overwrite,
                target: None,
            }),
        }
    }
}

impl Staged {
    /// Makes the staged output appear at the target and returns the target path, or flushes
    /// the writer and returns `None` for a stream.
    ///
    /// With [`Overwrite::Replace`], an existing file or directory at the target is replaced.
    /// A directory is set aside and restored if the staged one cannot be moved into place, so
    /// a failed commit leaves the previous output at the target. If the restore fails too, the
    /// previous output is kept at `previous` inside a holder directory next to the target, and
    /// the error's path names that location.
    ///
    /// # Errors
    ///
    /// [`MboxTurboError::TargetExists`] when the target appeared since staging and the policy
    /// is [`Overwrite::Refuse`], and [`MboxTurboError::Io`] when flushing or renaming fails. The
    /// staged output is removed on failure.
    pub fn commit(self) -> Result<Option<PathBuf>, MboxTurboError> {
        match (self.kind, self.target) {
            (Kind::Directory(directory), Some(path)) => {
                commit_directory(directory, path, self.overwrite).map(Some)
            },
            (Kind::File(file), Some(path)) => commit_file(file, path, self.overwrite).map(Some),
            (Kind::Stream(mut writer), _) => {
                writer
                    .flush()
                    .map_err(|source| MboxTurboError::io(Path::new(STREAM_LABEL), source))?;
                Ok(None)
            },
            (Kind::Directory(_) | Kind::File(_), None) => Ok(None),
        }
    }

    /// The destination to write to, matching the kind this sink accepted.
    ///
    /// A directory destination yields [`Output::Directory`]; a file or stream destination
    /// yields [`Output::Writer`].
    pub fn output(&mut self) -> Output<'_> {
        match &mut self.kind {
            Kind::Directory(directory) => Output::Directory(directory.path()),
            Kind::File(file) => Output::Writer(file),
            Kind::Stream(writer) => Output::Writer(writer.as_mut()),
        }
    }

    /// The final path, or `None` for a stream.
    #[must_use]
    pub fn target(&self) -> Option<&Path> {
        self.target.as_deref()
    }

    /// The path an error about this destination names: the target, or `<stream>` for a stream.
    #[must_use]
    pub fn target_label(&self) -> &Path {
        self.target().unwrap_or_else(|| Path::new(STREAM_LABEL))
    }

    /// The refusal a sink returns when handed an output kind it does not accept: an
    /// [`MboxTurboError::UnsupportedDestination`] naming the staged kind and its target.
    #[must_use]
    pub fn unsupported(&self) -> MboxTurboError {
        let kind = match self.kind {
            Kind::Directory(_) => DestinationKind::Directory,
            Kind::File(_) => DestinationKind::File,
            Kind::Stream(_) => DestinationKind::Stream,
        };
        MboxTurboError::UnsupportedDestination {
            kind,
            target: self.target.clone(),
        }
    }
}

/// Renames the staged directory onto `target`. When replacing, the existing output is set
/// aside first and restored if the staged directory cannot be put in place. If the restore
/// fails as well, the holder directory is kept and the error's path is where the previous
/// output now sits.
fn commit_directory(
    directory: TempDir,
    target: PathBuf,
    overwrite: Overwrite,
) -> Result<PathBuf, MboxTurboError> {
    commit_directory_with(directory, target, overwrite, |from, to| {
        fs::rename(from, to)
    })
}

/// [`commit_directory`] with the rename injectable, so a failing restore can be tested.
fn commit_directory_with(
    directory: TempDir,
    target: PathBuf,
    overwrite: Overwrite,
    rename: impl Fn(&Path, &Path) -> io::Result<()>,
) -> Result<PathBuf, MboxTurboError> {
    refuse_existing(&target, overwrite, DestinationKind::Directory)?;
    let set_aside = match overwrite {
        Overwrite::Replace => set_aside_existing(&target)?,
        Overwrite::Refuse => None,
    };
    let staged = directory.keep();
    let Err(source) = rename(&staged, &target) else {
        // The new output is in place; a leftover set-aside copy is not worth failing the commit.
        drop(set_aside);
        return Ok(target);
    };
    // The rename error is the one worth reporting; leftovers are cleaned up best effort.
    drop(fs::remove_dir_all(&staged));
    Err(match set_aside {
        Some(holder) => restore_previous(holder, &target, source, rename),
        None => MboxTurboError::io(&target, source),
    })
}

/// Moves the set-aside previous output back to `target` after the new output could not be put
/// there, and returns the error to report: `source` when the restore worked, otherwise an
/// error naming where the previous output is kept.
fn restore_previous(
    holder: TempDir,
    target: &Path,
    source: io::Error,
    rename: impl Fn(&Path, &Path) -> io::Result<()>,
) -> MboxTurboError {
    let previous = holder.path().join(SET_ASIDE);
    let Err(restore) = rename(&previous, target) else {
        return MboxTurboError::io(target, source);
    };
    // Dropping the holder would delete the previous output; keep it instead.
    drop(holder.keep());
    restore_failure(&previous, target, &restore, &source)
}

/// The error for a restore that failed after the commit rename failed; its path is where the
/// previous output now sits.
fn restore_failure(
    previous: &Path,
    target: &Path,
    restore: &io::Error,
    source: &io::Error,
) -> MboxTurboError {
    MboxTurboError::io(
        previous,
        io::Error::new(
            restore.kind(),
            format!(
                "restoring the previous output to {} failed ({restore}) after the new output \
                 could not be moved there ({source}); the previous output is at this path",
                target.display()
            ),
        ),
    )
}

/// Creates a staging directory in `parent` with the mode `fs::create_dir` would give it (the
/// umask still applies). The mode is pinned rather than left to tempfile's default, so the
/// committed directory, which is the staging directory renamed into place, does not depend on it.
fn staging_directory(parent: &Path) -> io::Result<TempDir> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o777))
            .tempdir_in(parent)
    }
    #[cfg(not(unix))]
    {
        TempDir::new_in(parent)
    }
}

/// Moves an existing file or directory at `target` into a fresh holder directory in the same
/// parent, so the move is a rename; `None` when nothing is at `target`. The holder is removed
/// when dropped.
fn set_aside_existing(target: &Path) -> Result<Option<TempDir>, MboxTurboError> {
    match fs::symlink_metadata(target) {
        Ok(_) => {},
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(MboxTurboError::io(target, source)),
    }
    let holder =
        TempDir::new_in(parent_of(target)).map_err(|source| MboxTurboError::io(target, source))?;
    fs::rename(target, holder.path().join(SET_ASIDE))
        .map_err(|source| MboxTurboError::io(target, source))?;
    Ok(Some(holder))
}

/// Persists the staged file at `target`, never replacing one that appeared after staging
/// unless replacing was asked for.
fn commit_file(
    mut file: NamedTempFile,
    target: PathBuf,
    overwrite: Overwrite,
) -> Result<PathBuf, MboxTurboError> {
    file.flush()
        .map_err(|source| MboxTurboError::io(&target, source))?;
    refuse_existing(&target, overwrite, DestinationKind::File)?;
    let persisted: Result<File, _> = match overwrite {
        Overwrite::Refuse => file.persist_noclobber(&target),
        Overwrite::Replace => file.persist(&target),
    };
    match persisted {
        Ok(_) => Ok(target),
        Err(failure)
            if overwrite == Overwrite::Refuse
                && failure.error.kind() == io::ErrorKind::AlreadyExists =>
        {
            Err(MboxTurboError::TargetExists { path: target })
        },
        Err(failure) => Err(MboxTurboError::io(&target, failure.error)),
    }
}

/// The directory a target's staging area lives in: its parent, or the working directory for
/// a bare file name.
fn parent_of(target: &Path) -> &Path {
    target
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// Fails when `target` exists and may not be replaced by output of `kind`.
///
/// Without [`Overwrite::Replace`] any existing target is refused with
/// [`MboxTurboError::TargetExists`]. With it, a target of the other kind and a directory that is
/// neither empty nor holds a [`MANIFEST`] from an earlier export are refused with
/// [`MboxTurboError::TargetNotReplaceable`].
fn refuse_existing(
    target: &Path,
    overwrite: Overwrite,
    kind: DestinationKind,
) -> Result<(), MboxTurboError> {
    if overwrite == Overwrite::Replace {
        return refuse_unreplaceable(target, kind);
    }
    let exists = target
        .try_exists()
        .map_err(|source| MboxTurboError::io(target, source))?;
    if exists {
        return Err(MboxTurboError::TargetExists {
            path: target.to_path_buf(),
        });
    }
    Ok(())
}

/// The replace-path half of [`refuse_existing`]: nothing at `target` is fine, a target of the
/// wanted kind is fine unless it is an unrelated directory.
fn refuse_unreplaceable(target: &Path, kind: DestinationKind) -> Result<(), MboxTurboError> {
    let metadata = match fs::symlink_metadata(target) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => return Err(MboxTurboError::io(target, source)),
    };
    let reason = match (kind, metadata.is_dir()) {
        (DestinationKind::Directory, false) => "a file where a directory goes",
        (DestinationKind::File, true) => "a directory where a file goes",
        (DestinationKind::Directory, true) if !is_replaceable_directory(target)? => {
            "a directory that is not empty and holds no manifest.jsonl from an earlier export"
        },
        _ => return Ok(()),
    };
    Err(MboxTurboError::TargetNotReplaceable {
        path: target.to_path_buf(),
        reason,
    })
}

/// Whether `directory` is empty or holds a [`MANIFEST`].
fn is_replaceable_directory(directory: &Path) -> Result<bool, MboxTurboError> {
    let has_manifest = directory
        .join(MANIFEST)
        .try_exists()
        .map_err(|source| MboxTurboError::io(directory, source))?;
    if has_manifest {
        return Ok(true);
    }
    let mut entries =
        fs::read_dir(directory).map_err(|source| MboxTurboError::io(directory, source))?;
    Ok(entries.next().is_none())
}

#[cfg(test)]
mod tests {
    use std::{fs, io};

    use tempfile::TempDir;

    use super::{Overwrite, commit_directory_with};
    use crate::error::MboxTurboError;

    #[test]
    fn a_failed_restore_keeps_the_previous_output_at_the_path_the_error_names() {
        let parent = TempDir::new().expect("the parent temp directory is created");
        let target = parent.path().join("out");
        fs::create_dir_all(&target).expect("previous output creates");
        fs::write(target.join("old.txt"), b"previous").expect("previous output is written");
        fs::write(target.join("manifest.jsonl"), b"").expect("previous manifest is written");
        let staged = TempDir::new_in(parent.path()).expect("staged directory creates");

        let error = commit_directory_with(staged, target.clone(), Overwrite::Replace, |_, _| {
            Err(io::Error::other("injected rename failure"))
        })
        .expect_err("both renames fail");

        let MboxTurboError::Io { path, .. } = error else {
            panic!("a failed restore reports an I/O error");
        };
        assert_eq!(
            fs::read(path.join("old.txt")).expect("previous output survives at the named path"),
            b"previous",
            "the previous output is kept, not deleted with its holder",
        );
        assert!(!target.exists(), "nothing was restored at the target");
    }
}
