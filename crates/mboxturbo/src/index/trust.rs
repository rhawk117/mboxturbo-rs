//! Loading a sidecar: the trust check on the opened file, then mapping and header parsing.

use std::fs::{self, File};
use std::io;
use std::path::Path;
use std::sync::Arc;

use memmap2::Mmap;

use super::format::Layout;
use super::{Backing, Index};
use crate::error::MboxTurboError;
use crate::fingerprint::Fingerprint;
use crate::mailbox::map_read_only;

/// Why a sidecar is not mapped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    /// The sidecar belongs to a different user than the mbox.
    #[cfg(unix)]
    ForeignOwner,
    /// The sidecar is a symlink, FIFO, directory, socket or anything else but a regular file.
    NotRegularFile,
    /// The path named another file when it was opened than when it was inspected.
    #[cfg(unix)]
    Replaced,
}

impl Refusal {
    /// The reason, as carried by the error the refusal becomes.
    const fn reason(self) -> &'static str {
        match self {
            #[cfg(unix)]
            Self::ForeignOwner => "the sidecar is owned by another user than the mbox",
            Self::NotRegularFile => "the sidecar is not a regular file",
            #[cfg(unix)]
            Self::Replaced => "the sidecar was replaced while it was opened",
        }
    }
}

/// Device, inode and owner of a file, the values the sidecar trust rules compare.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    /// Device holding the file.
    device: u64,
    /// Inode number on that device.
    inode: u64,
    /// Owning user id.
    owner: u32,
}

#[cfg(unix)]
impl Identity {
    /// The identity `metadata` reports.
    fn of(metadata: &fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;

        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
        }
    }
}

impl Index {
    /// Maps the opened index `file`, which was opened from `path`, and checks its header.
    fn from_file(
        file: &File,
        path: &Path,
        mailbox: Arc<Mmap>,
        expected: Fingerprint,
    ) -> Result<Self, MboxTurboError> {
        let mapped = map_read_only(file).map_err(|source| MboxTurboError::io(path, source))?;
        let layout = Layout::parse(&mapped, expected).map_err(|rejection| rejection.at(path))?;
        let origin = Some(path.to_path_buf());
        Ok(Self::new(mailbox, Backing::Mapped(mapped), layout, origin))
    }

    /// Maps the index file at `path` and checks its header against the mailbox `expected`
    /// identifies, whose mapping `mailbox` is kept for a rebuild. Only the header is read here;
    /// blocks are checked when lookups reach them.
    ///
    /// # Errors
    ///
    /// [`MboxTurboError::Io`] when the file cannot be opened or mapped,
    /// [`MboxTurboError::CorruptIndex`] when its header or length fails validation, and
    /// [`MboxTurboError::StaleIndex`] when it was written by an older format or for a different
    /// mailbox than `expected`.
    pub fn load(
        path: &Path,
        mailbox: Arc<Mmap>,
        expected: Fingerprint,
    ) -> Result<Self, MboxTurboError> {
        let file = File::open(path).map_err(|source| MboxTurboError::io(path, source))?;
        Self::from_file(&file, path, mailbox, expected)
    }

    /// Like [`Index::load`] for the sidecar of the mbox at `mbox`, but maps `sidecar` only when
    /// it is a regular file, not a symlink, FIFO, directory or socket, that was not swapped for
    /// another file while it was opened and, on Unix, is owned by the user who owns the mbox.
    /// The checks and the mapping use the same open file.
    ///
    /// # Errors
    ///
    /// [`MboxTurboError::Io`] with [`io::ErrorKind::PermissionDenied`] when the sidecar is
    /// refused, and the errors of [`Index::load`] otherwise.
    pub(crate) fn load_trusted(
        sidecar: &Path,
        mbox: &Path,
        mailbox: Arc<Mmap>,
        expected: Fingerprint,
    ) -> Result<Self, MboxTurboError> {
        let file = open_trusted(sidecar, mbox)?;
        Self::from_file(&file, sidecar, mailbox, expected)
    }
}

/// Refuses an opened sidecar that is not the file `inspected` or not owned by the mbox's owner.
#[cfg(unix)]
fn check_opened(
    file: &File,
    inspected: &fs::Metadata,
    sidecar: &Path,
    mbox: &Path,
) -> Result<(), MboxTurboError> {
    use std::os::unix::fs::MetadataExt as _;

    let opened = file
        .metadata()
        .map_err(|source| MboxTurboError::io(sidecar, source))?;
    let owner = fs::metadata(mbox)
        .map_err(|source| MboxTurboError::io(mbox, source))?
        .uid();
    judge(Identity::of(inspected), Identity::of(&opened), owner)
        .map_err(|refusal| refused(sidecar, refusal))
}

/// Without ownership and inode data the `lstat` check alone applies.
#[cfg(not(unix))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "shares its signature with the Unix check"
)]
fn check_opened(
    _file: &File,
    _inspected: &fs::Metadata,
    _sidecar: &Path,
    _mbox: &Path,
) -> Result<(), MboxTurboError> {
    Ok(())
}

/// Whether the sidecar `opened` is the file `inspected` earlier and is owned by `mbox_owner`.
/// std has no `getuid`, so the mbox's owner stands for the current user.
#[cfg(unix)]
const fn judge(inspected: Identity, opened: Identity, mbox_owner: u32) -> Result<(), Refusal> {
    if inspected.device != opened.device || inspected.inode != opened.inode {
        return Err(Refusal::Replaced);
    }
    if opened.owner != mbox_owner {
        return Err(Refusal::ForeignOwner);
    }
    Ok(())
}

/// The error a refusal of `sidecar` becomes.
fn refused(sidecar: &Path, refusal: Refusal) -> MboxTurboError {
    let source = io::Error::new(io::ErrorKind::PermissionDenied, refusal.reason());
    MboxTurboError::io(sidecar, source)
}

/// Opens `sidecar` for reading once it is known to be a regular file owned by the mbox's owner.
/// The path is inspected with `lstat` before it is opened, because opening a FIFO blocks, and
/// the opened file is inspected again to catch a swap between the two calls.
fn open_trusted(sidecar: &Path, mbox: &Path) -> Result<File, MboxTurboError> {
    let inspected =
        fs::symlink_metadata(sidecar).map_err(|source| MboxTurboError::io(sidecar, source))?;
    if !inspected.is_file() {
        return Err(refused(sidecar, Refusal::NotRegularFile));
    }
    let file = File::open(sidecar).map_err(|source| MboxTurboError::io(sidecar, source))?;
    check_opened(&file, &inspected, sidecar, mbox)?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    mod trust {
        use super::super::{Identity, Refusal, judge};

        const OWNER: u32 = 1000;

        const fn identity(inode: u64, owner: u32) -> Identity {
            Identity {
                device: 1,
                inode,
                owner,
            }
        }

        #[test]
        fn a_sidecar_owned_by_the_mbox_owner_is_trusted() {
            assert_eq!(judge(identity(7, OWNER), identity(7, OWNER), OWNER), Ok(()));
        }

        #[test]
        fn a_sidecar_owned_by_another_user_is_refused() {
            assert_eq!(
                judge(identity(7, 0), identity(7, 0), OWNER),
                Err(Refusal::ForeignOwner)
            );
        }

        #[test]
        fn a_path_that_names_another_inode_when_opened_is_refused() {
            assert_eq!(
                judge(identity(7, OWNER), identity(8, OWNER), OWNER),
                Err(Refusal::Replaced)
            );
        }

        #[test]
        fn a_path_that_names_another_device_when_opened_is_refused() {
            let moved = Identity {
                device: 2,
                ..identity(7, OWNER)
            };
            assert_eq!(
                judge(identity(7, OWNER), moved, OWNER),
                Err(Refusal::Replaced)
            );
        }
    }
}
