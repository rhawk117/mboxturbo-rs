//! How a [`Mailbox`] is opened: where its index lives and how large its blocks are.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::error::MboxTurboError;
use crate::mailbox::{Mailbox, Mapped};

/// Most entries a block may hold.
const MAX_ENTRIES: usize = 0x1_0000;

/// Fewest entries a block may hold.
const MIN_ENTRIES: usize = 2;

/// Suffix appended to the mbox path to name its sidecar index file.
const SIDECAR_SUFFIX: &str = ".mbxidx";

/// How many messages one block of the index covers: a power of two from 2 to 65536.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockSize(u8);

impl BlockSize {
    /// The number of messages in one block.
    #[must_use]
    pub const fn entries(self) -> usize {
        #[expect(
            clippy::as_conversions,
            reason = "widening a shift of at most 16 to u32 cannot lose bits"
        )]
        let shift = self.0 as u32;
        1_usize << shift
    }

    /// A block of `entries` messages, or `None` unless `entries` is a power of two between 2 and
    /// 65536 inclusive, the range the index file header can describe.
    #[must_use]
    pub const fn new(entries: usize) -> Option<Self> {
        if !entries.is_power_of_two() || entries < MIN_ENTRIES || entries > MAX_ENTRIES {
            return None;
        }
        #[expect(
            clippy::cast_possible_truncation,
            clippy::as_conversions,
            reason = "entries is a power of two of at most 65536, so its shift is at most 16"
        )]
        let shift = entries.trailing_zeros() as u8;
        Some(Self(shift))
    }

    /// The header's block shift: `entries()` is `1 << shift()`.
    pub(crate) const fn shift(self) -> u8 {
        self.0
    }
}

/// Where [`MailboxBuilder::open`] keeps the message index.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum IndexPolicy {
    /// An index held in memory only. Nothing is read from or written to disk.
    Memory,
    /// The index file at this path, with the semantics of [`Mailbox::open_cached`]: a missing
    /// or stale file is rebuilt and written, while a damaged header or a failed write is an
    /// error for the caller.
    Path(PathBuf),
    /// The file `<mbox path>.mbxidx` beside the mbox, so `/a/mail.mbox` is indexed by
    /// `/a/mail.mbox.mbxidx`. It is reused while it matches the mbox and rebuilt when it is
    /// missing, stale or damaged. When it cannot be written, for example in a read-only
    /// directory, the open still succeeds with an index held in memory only.
    #[default]
    Sidecar,
}

/// Where the index a [`Mailbox`] serves came from.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IndexSource {
    /// The index was read from, or just written to, this file.
    File(PathBuf),
    /// The index exists only in memory.
    Memory,
}

/// Opens a [`Mailbox`] with a chosen index location and block size.
///
/// The default is the [`IndexPolicy::Sidecar`] policy with the default block size, which is what
/// [`Mailbox::open`] uses.
#[derive(Clone, Debug, Default)]
pub struct MailboxBuilder {
    /// Block size for an index built by this open, or `None` for the default.
    block_size: Option<BlockSize>,
    /// Where the index is kept.
    policy: IndexPolicy,
}

impl MailboxBuilder {
    /// Sets the block size of an index this open builds. An index loaded from a file keeps the
    /// block size it was written with.
    #[must_use]
    pub const fn block_size(mut self, size: BlockSize) -> Self {
        self.block_size = Some(size);
        self
    }

    /// Chooses where the index is kept.
    #[must_use]
    pub fn index(mut self, policy: IndexPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// A builder with the sidecar index policy and the default block size.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Maps the mbox at `path` and attaches its index according to the policy.
    ///
    /// # Errors
    ///
    /// [`MboxTurboError::Io`] when the mbox cannot be opened or mapped. With
    /// [`IndexPolicy::Path`], also when the index file cannot be read or the rebuilt index
    /// cannot be written, and [`MboxTurboError::CorruptIndex`] when its header is damaged. The
    /// sidecar and memory policies never fail on the index.
    pub fn open<P>(&self, path: P) -> Result<Mailbox, MboxTurboError>
    where
        P: AsRef<Path>,
    {
        let mbox = path.as_ref();
        let mapped = Mapped::open(mbox)?;
        match &self.policy {
            IndexPolicy::Memory => {
                let index = mapped.build(self.block_size);
                Ok(mapped.with_index(index, IndexSource::Memory))
            },
            IndexPolicy::Path(index_path) => self.open_at(mapped, index_path),
            IndexPolicy::Sidecar => self.open_sidecar(mapped, &sidecar_path(mbox)),
        }
    }

    /// Serves the index at `index_path`, rebuilding and saving it when it is missing or stale;
    /// any other failure propagates.
    fn open_at(&self, mapped: Mapped, index_path: &Path) -> Result<Mailbox, MboxTurboError> {
        let source = IndexSource::File(index_path.to_path_buf());
        match mapped.load(index_path) {
            Ok(index) => Ok(mapped.with_index(index, source)),
            Err(error) if error.calls_for_rebuild() => {
                let index = mapped.build(self.block_size);
                index.save(index_path)?;
                Ok(mapped.with_index(index, source))
            },
            Err(error) => Err(error),
        }
    }

    /// Serves the sidecar at `sidecar` when it loads, else rebuilds it. A rebuild that cannot be
    /// written is kept in memory, because a cache the caller never named must not fail the open.
    fn open_sidecar(&self, mapped: Mapped, sidecar: &Path) -> Result<Mailbox, MboxTurboError> {
        if let Ok(index) = mapped.load(sidecar) {
            return Ok(mapped.with_index(index, IndexSource::File(sidecar.to_path_buf())));
        }
        let index = mapped.build(self.block_size);
        let source = match index.save(sidecar) {
            Ok(()) => IndexSource::File(sidecar.to_path_buf()),
            Err(MboxTurboError::Io { .. }) => IndexSource::Memory,
            Err(error) => return Err(error),
        };
        Ok(mapped.with_index(index, source))
    }
}

/// The sidecar index file for the mbox at `mbox`: its path with `.mbxidx` appended.
pub(crate) fn sidecar_path(mbox: &Path) -> PathBuf {
    let mut name = OsString::from(mbox);
    name.push(SIDECAR_SUFFIX);
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use super::{BlockSize, IndexPolicy, IndexSource, MailboxBuilder, sidecar_path};
    use crate::Mailbox;

    const MBOX: &[u8] = b"From a@example.com Mon Jan  1 00:00:00 2024\nSubject: one\n\nbody\n\
From b@example.com Tue Jan  2 00:00:00 2024\nSubject: two\n\nbody\n\
From c@example.com Wed Jan  3 00:00:00 2024\nSubject: three\n\nbody\n";

    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::tempdir().expect("temp directory is created");
        let path = directory.path().join("mail.mbox");
        fs::write(&path, MBOX).expect("fixture mbox is written");
        (directory, path)
    }

    fn entries(directory: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(directory)
            .expect("directory is listed")
            .map(|entry| {
                entry
                    .expect("directory entry is read")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    #[test]
    fn the_sidecar_name_appends_to_the_whole_file_name() {
        assert_eq!(
            sidecar_path(Path::new("/a/mail.mbox")),
            PathBuf::from("/a/mail.mbox.mbxidx"),
            "the suffix is appended, not swapped for the extension"
        );
    }

    #[test]
    fn open_leaves_a_sidecar_that_the_next_open_serves() {
        let (_directory, path) = fixture();
        let sidecar = sidecar_path(&path);
        let first = Mailbox::open(&path).expect("first open succeeds");
        assert_eq!(
            first.index_source(),
            IndexSource::File(sidecar.clone()),
            "a writable directory gets its sidecar"
        );
        assert!(sidecar.is_file(), "the sidecar exists after the first open");
        let before = fs::read(&sidecar).expect("sidecar is read");
        let second = Mailbox::open(&path).expect("second open succeeds");
        assert_eq!(
            second.index_source(),
            IndexSource::File(sidecar.clone()),
            "the second open reports the sidecar"
        );
        assert_eq!(second.len(), 3, "the served index counts every message");
        assert_eq!(
            fs::read(&sidecar).expect("sidecar is read again"),
            before,
            "the second open did not change the sidecar"
        );
    }

    #[cfg(unix)]
    #[test]
    fn serving_the_sidecar_does_not_rewrite_it() {
        use std::os::unix::fs::MetadataExt as _;

        let (_directory, path) = fixture();
        let sidecar = sidecar_path(&path);
        let _first = Mailbox::open(&path).expect("first open succeeds");
        let inode = |file: &Path| fs::metadata(file).expect("sidecar has metadata").ino();
        let written = inode(&sidecar);
        let _second = Mailbox::open(&path).expect("second open succeeds");
        assert_eq!(
            inode(&sidecar),
            written,
            "a rewrite would rename a new file over the sidecar and change its inode"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_read_only_directory_opens_in_memory_and_stays_untouched() {
        use std::os::unix::fs::PermissionsExt as _;

        struct Restore<'dir>(&'dir Path);
        impl Drop for Restore<'_> {
            fn drop(&mut self) {
                fs::set_permissions(self.0, fs::Permissions::from_mode(0o755))
                    .expect("directory permissions are restored");
            }
        }

        let (directory, path) = fixture();
        let _restore = Restore(directory.path());
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o555))
            .expect("directory is made read-only");
        let probe = directory.path().join("probe");
        if fs::write(&probe, b"").is_ok() {
            fs::remove_file(&probe).expect("probe file is removed");
            return;
        }
        let mailbox = Mailbox::open(&path).expect("a read-only directory still opens");
        assert_eq!(
            mailbox.index_source(),
            IndexSource::Memory,
            "an unwritable sidecar leaves an in-memory index"
        );
        assert_eq!(mailbox.len(), 3, "the in-memory index serves every message");
        assert_eq!(
            entries(directory.path()),
            vec!["mail.mbox".to_owned()],
            "no sidecar or temp file is left behind"
        );
    }

    #[test]
    fn the_memory_policy_never_writes() {
        let (directory, path) = fixture();
        let mailbox = MailboxBuilder::new()
            .index(IndexPolicy::Memory)
            .open(&path)
            .expect("memory policy opens");
        assert_eq!(
            mailbox.index_source(),
            IndexSource::Memory,
            "the memory policy reports memory"
        );
        assert_eq!(mailbox.len(), 3, "the memory index counts every message");
        assert_eq!(
            entries(directory.path()),
            vec!["mail.mbox".to_owned()],
            "the directory holds only the mbox"
        );
    }

    #[test]
    fn the_path_policy_writes_the_given_path() {
        let (directory, path) = fixture();
        let index_path = directory.path().join("named.idx");
        let mailbox = MailboxBuilder::new()
            .index(IndexPolicy::Path(index_path.clone()))
            .open(&path)
            .expect("path policy opens");
        assert_eq!(
            mailbox.index_source(),
            IndexSource::File(index_path.clone()),
            "the named file is the source"
        );
        assert_eq!(
            entries(directory.path()),
            vec!["mail.mbox".to_owned(), "named.idx".to_owned()],
            "only the named index is written, with no sidecar"
        );
        let reopened = Mailbox::open_cached(&path, &index_path).expect("named index reopens");
        assert_eq!(reopened.len(), 3, "the written index serves every message");
    }

    #[test]
    fn a_block_size_of_1024_is_written_to_the_header() {
        let (directory, path) = fixture();
        let index_path = directory.path().join("blocks.idx");
        let size = BlockSize::new(1024).expect("1024 is a valid block size");
        let _mailbox = MailboxBuilder::new()
            .index(IndexPolicy::Path(index_path.clone()))
            .block_size(size)
            .open(&path)
            .expect("builder opens with a block size");
        let bytes = fs::read(&index_path).expect("index file is read");
        assert_eq!(
            bytes.get(12),
            Some(&10),
            "the header's block shift is log2(1024)"
        );
    }

    #[cfg(unix)]
    #[test]
    #[expect(
        clippy::filetype_is_file,
        reason = "the symlink must have become a regular file, not a directory or another link"
    )]
    fn a_sidecar_symlink_is_replaced_and_its_target_left_alone() {
        use std::os::unix::fs::symlink;

        let (directory, path) = fixture();
        let target = directory.path().join("target.bin");
        fs::write(&target, b"not an index").expect("target is written");
        let sidecar = sidecar_path(&path);
        symlink(&target, &sidecar).expect("symlink is created");
        let mailbox = Mailbox::open(&path).expect("open replaces the link");
        assert_eq!(
            mailbox.index_source(),
            IndexSource::File(sidecar.clone()),
            "the rebuilt sidecar is the source"
        );
        assert!(
            fs::symlink_metadata(&sidecar)
                .expect("sidecar has metadata")
                .file_type()
                .is_file(),
            "the link became a regular file"
        );
        assert_eq!(
            fs::read(&target).expect("target is read"),
            b"not an index",
            "the link's target is unchanged"
        );
    }

    #[test]
    fn block_size_accepts_only_powers_of_two_from_2_to_65536() {
        for refused in [0, 1, 3, 1000, 0x2_0000] {
            assert_eq!(BlockSize::new(refused), None, "{refused} is refused");
        }
        for accepted in [2, 1024, 0x1_0000] {
            assert_eq!(
                BlockSize::new(accepted).map(BlockSize::entries),
                Some(accepted),
                "{accepted} round-trips through entries"
            );
        }
    }
}
