//! An mbox file mapped read-only together with its message index.

use std::fs::File;
use std::io;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

use memmap2::Mmap;
use rayon::prelude::*;

use crate::error::Error;
use crate::fingerprint::Fingerprint;
use crate::hint;
use crate::index::Index;
use crate::message::Message;

/// An mbox file mapped read-only, with the byte offset of every message.
///
/// The file must not be modified or truncated while the mailbox, or any [`Message`] taken
/// from it, is alive.
#[derive(Debug)]
pub struct Mailbox {
    contents: Arc<Mmap>,
    index: Index,
}

#[derive(Debug)]
struct Mapped {
    contents: Mmap,
    fingerprint: Fingerprint,
}

impl Mapped {
    fn open(path: &Path) -> Result<Self, Error> {
        let file = File::open(path).map_err(|source| Error::io(path, source))?;
        let modified = file
            .metadata()
            .and_then(|metadata| metadata.modified())
            .ok();
        let contents = map_read_only(&file).map_err(|source| Error::io(path, source))?;
        let fingerprint = Fingerprint::new(&contents, modified);
        Ok(Self {
            contents,
            fingerprint,
        })
    }

    fn into_indexed(self) -> Mailbox {
        let index = Index::build(&self.contents, self.fingerprint);
        Mailbox {
            contents: Arc::new(self.contents),
            index,
        }
    }

    fn with_index(self, index: Index) -> Mailbox {
        Mailbox {
            contents: Arc::new(self.contents),
            index,
        }
    }
}

#[expect(
    unsafe_code,
    reason = "a read-only map is sound while the file is neither written nor truncated, which \
              is the documented contract of Mailbox and of every Message borrowed from it"
)]
#[expect(
    clippy::undocumented_unsafe_blocks,
    reason = "the safety argument is the reason on the unsafe_code expectation; the crate keeps \
              code free of comments"
)]
fn map_read_only(file: &File) -> io::Result<Mmap> {
    unsafe { Mmap::map(file) }
}

impl Mailbox {
    /// Maps the mbox at `path` and indexes it on all rayon threads.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the file cannot be opened or mapped.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        Ok(Mapped::open(path.as_ref())?.into_indexed())
    }

    /// Maps the mbox at `path`, reusing the index saved at `index_path` when it still matches
    /// the mailbox. When it is missing or stale, a new index is built and saved there.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when either file cannot be read or the new index cannot be written, and
    /// [`Error::CorruptIndex`] when `index_path` exists but fails validation; a corrupt file is
    /// left in place for inspection rather than overwritten.
    pub fn open_cached(
        path: impl AsRef<Path>,
        index_path: impl AsRef<Path>,
    ) -> Result<Self, Error> {
        let index_path = index_path.as_ref();
        let mapped = Mapped::open(path.as_ref())?;
        match Index::load(index_path, mapped.fingerprint) {
            Ok(index) => Ok(mapped.with_index(index)),
            Err(error) if error.calls_for_rebuild() => {
                let mailbox = mapped.into_indexed();
                mailbox.index.save(index_path)?;
                Ok(mailbox)
            }
            Err(error) => Err(error),
        }
    }

    /// The message index.
    #[must_use]
    pub const fn index(&self) -> &Index {
        &self.index
    }

    /// Number of messages.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.index.len()
    }

    /// Whether the mailbox holds no messages.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Raw bytes of the message at `position`, including its `From ` separator line.
    #[must_use]
    pub fn raw(&self, position: usize) -> Option<&[u8]> {
        self.contents.get(self.index.span(position)?)
    }

    /// Raw bytes of every message, in file order.
    #[must_use]
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &[u8]> + DoubleEndedIterator {
        (0..self.len()).map(|position| self.raw(position).unwrap_or_default())
    }

    /// Raw bytes of every message, split across rayon threads.
    #[must_use]
    pub fn par_iter(&self) -> impl IndexedParallelIterator<Item = &[u8]> {
        (0..self.len())
            .into_par_iter()
            .map(|position| self.raw(position).unwrap_or_default())
    }

    /// The message at `position`, parsed lazily on first field access.
    #[must_use]
    pub fn message(&self, position: usize) -> Option<Message> {
        Some(Message::new(
            Arc::clone(&self.contents),
            self.index.span(position)?,
        ))
    }

    /// The messages at `positions` (clamped to those that exist), all parsed in parallel.
    #[must_use]
    pub fn parse_batch(&self, positions: Range<usize>) -> Vec<Message> {
        let end = positions.end.min(self.len());
        (positions.start.min(end)..end)
            .into_par_iter()
            .filter_map(|position| self.message(position))
            .inspect(|message| {
                let _found_mime_part = message.parse();
            })
            .collect()
    }

    /// Asks the kernel to start reading the messages at `positions` in the background.
    pub fn prefetch(&self, positions: Range<usize>) {
        if let Some(span) = self.index.span_of(positions) {
            hint::read_ahead(&self.contents, span);
        }
    }
}
