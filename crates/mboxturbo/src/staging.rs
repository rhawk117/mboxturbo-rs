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
                refuse_existing(&target, overwrite)?;
                let directory = TempDir::new_in(parent_of(&target))
                    .map_err(|source| MboxTurboError::io(&target, source))?;
                Ok(Staged {
                    kind: Kind::Directory(directory),
                    overwrite,
                    target: Some(target),
                })
            },
            Self::File(target) => {
                refuse_existing(&target, overwrite)?;
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
                    .map_err(|source| MboxTurboError::io(Path::new("<stream>"), source))?;
                Ok(None)
            },
            (Kind::Directory(_) | Kind::File(_), None) => Ok(None),
        }
    }

    /// The staging directory to fill for a directory destination; `None` otherwise.
    #[must_use]
    pub fn directory(&self) -> Option<&Path> {
        match &self.kind {
            Kind::Directory(directory) => Some(directory.path()),
            Kind::File(_) | Kind::Stream(_) => None,
        }
    }

    /// The final path, or `None` for a stream.
    #[must_use]
    pub fn target(&self) -> Option<&Path> {
        self.target.as_deref()
    }

    /// The writer for a file or stream destination; `None` for a directory.
    pub fn writer(&mut self) -> Option<&mut (dyn Write + Send)> {
        match &mut self.kind {
            Kind::Directory(_) => None,
            Kind::File(file) => Some(file),
            Kind::Stream(writer) => Some(writer.as_mut()),
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
    refuse_existing(&target, overwrite)?;
    let set_aside = match overwrite {
        Overwrite::Replace => set_aside_existing(&target)?,
        Overwrite::Refuse => None,
    };
    let staged = directory.keep();
    if let Err(source) = rename(&staged, &target) {
        // The rename error is the one worth reporting; leftovers are cleaned up best effort.
        drop(fs::remove_dir_all(&staged));
        if let Some(holder) = set_aside {
            let previous = holder.path().join(SET_ASIDE);
            if let Err(restore) = rename(&previous, &target) {
                // Dropping the holder would delete the previous output; keep it instead.
                drop(holder.keep());
                return Err(MboxTurboError::io(
                    &previous,
                    io::Error::new(
                        restore.kind(),
                        format!(
                            "restoring the previous output to {} failed ({restore}) after \
                             the new output could not be moved there ({source}); the \
                             previous output is at this path",
                            target.display()
                        ),
                    ),
                ));
            }
        }
        return Err(MboxTurboError::io(&target, source));
    }
    // The new output is in place; a leftover set-aside copy is not worth failing the commit.
    drop(set_aside);
    Ok(target)
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

/// Fails with [`MboxTurboError::TargetExists`] when `target` exists and may not be replaced.
fn refuse_existing(target: &Path, overwrite: Overwrite) -> Result<(), MboxTurboError> {
    if overwrite == Overwrite::Replace {
        return Ok(());
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
