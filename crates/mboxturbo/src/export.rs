//! The export driver: one place that owns selection, progress, cancellation, overwrite
//! refusal and staging, so a format only has to write batches.

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use arrow_array::RecordBatch;
use arrow_schema::{ArrowError, SchemaRef};

use crate::error::MboxTurboError;
use crate::mailbox::Mailbox;
use crate::pipeline::{BatchReader, Pipeline};
use crate::selection::Selection;
use crate::staging::{Destination, ExportSummary, Overwrite, Staged};

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

#[expect(
    clippy::multiple_inherent_impl,
    reason = "the destination kind is the driver's concept; staging.rs does not know it"
)]
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
    fn path(&self) -> Option<PathBuf> {
        match self {
            Self::Directory(path) | Self::File(path) => Some(path.clone()),
            Self::Stream(_) => None,
        }
    }
}

/// A flag that asks a running export to stop, shared between clones and threads.
#[derive(Debug, Clone, Default)]
pub struct CancelToken {
    /// Set once cancellation is requested.
    flag: Arc<AtomicBool>,
}

impl CancelToken {
    /// Asks every export holding a clone of this token to stop after its current batch.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Release);
    }

    /// Whether [`CancelToken::cancel`] has been called on this token or any clone.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }

    /// A token that has not been cancelled.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// How far an export has got, reported after each written batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Progress {
    /// Bytes written so far.
    pub bytes: u64,
    /// Messages written so far.
    pub messages: u64,
    /// Messages the selection yields in total.
    pub total: u64,
}

/// A format that writes batches into a staged destination.
///
/// The [`Export`] driver does everything else: it validates the selection, refuses an
/// existing target, stages the output, streams batches, reports progress, honours
/// cancellation and commits. Implementations only encode.
///
/// The driver calls [`accepts`](Self::accepts) first, then [`begin`](Self::begin) once,
/// [`write`](Self::write) once per batch in selection order, and [`finish`](Self::finish)
/// once if every batch was written.
pub trait Exporter: Send {
    /// Whether this format can be written to a destination of `kind`. Checked before anything
    /// is staged or extracted.
    fn accepts(&self, kind: DestinationKind) -> bool;

    /// Prepares to receive batches of `schema`, for example by writing a header.
    ///
    /// # Errors
    ///
    /// Any [`MboxTurboError`]; the driver discards the staged output and returns it.
    fn begin(&mut self, schema: &SchemaRef, staged: &mut Staged) -> Result<(), MboxTurboError>;

    /// Completes the output after the last batch, for example by writing a footer.
    ///
    /// # Errors
    ///
    /// Any [`MboxTurboError`]; the driver discards the staged output and returns it.
    fn finish(&mut self, staged: &mut Staged) -> Result<(), MboxTurboError>;

    /// Writes one batch and returns the bytes it added to the output.
    ///
    /// # Errors
    ///
    /// Any [`MboxTurboError`]; the driver discards the staged output and returns it.
    fn write(&mut self, batch: &RecordBatch, staged: &mut Staged) -> Result<u64, MboxTurboError>;
}

/// Progress callback type.
type ProgressHook = Box<dyn FnMut(Progress) + Send>;

/// An export of a selection of a mailbox to a destination, run with [`Export::run`].
///
/// The defaults are every message and [`Overwrite::Refuse`].
pub struct Export {
    /// Raised to stop the export.
    cancel: Option<CancelToken>,
    /// Where the output goes.
    destination: Destination,
    /// The mailbox to read.
    mailbox: Arc<Mailbox>,
    /// Whether an existing target is replaced.
    overwrite: Overwrite,
    /// The columns to extract.
    pipeline: Arc<Pipeline>,
    /// Called after each written batch.
    progress: Option<ProgressHook>,
    /// Which messages to export.
    selection: Selection,
}

impl fmt::Debug for Export {
    #[expect(
        clippy::renamed_function_params,
        reason = "the trait calls it `f`, a one-letter name the min_ident_chars lint bans"
    )]
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Export")
            .field("destination", &self.destination)
            .field("overwrite", &self.overwrite)
            .field("selection", &self.selection)
            .finish_non_exhaustive()
    }
}

impl Export {
    /// Stops the export, within one batch, once `token` is cancelled.
    #[must_use]
    pub fn cancel_token(mut self, token: CancelToken) -> Self {
        self.cancel = Some(token);
        self
    }

    /// An export of every message of `mailbox` through `pipeline` to `destination`.
    #[must_use]
    pub fn new(pipeline: Arc<Pipeline>, mailbox: Arc<Mailbox>, destination: Destination) -> Self {
        Self {
            cancel: None,
            destination,
            mailbox,
            overwrite: Overwrite::Refuse,
            pipeline,
            progress: None,
            selection: Selection::All,
        }
    }

    /// Calls `hook` after each written batch.
    #[must_use]
    pub fn on_progress<Hook>(mut self, hook: Hook) -> Self
    where
        Hook: FnMut(Progress) + Send + 'static,
    {
        self.progress = Some(Box::new(hook));
        self
    }

    /// What to do when the target already exists.
    #[must_use]
    pub const fn overwrite(mut self, overwrite: Overwrite) -> Self {
        self.overwrite = overwrite;
        self
    }

    /// Runs the export through `exporter`.
    ///
    /// The selection is validated and the destination kind checked before anything is staged.
    /// On cancellation or any error the staged output is removed and nothing is left at the
    /// target or beside it.
    ///
    /// # Errors
    ///
    /// [`MboxTurboError::PositionOutOfRange`] for a bad selection,
    /// [`MboxTurboError::UnsupportedDestination`] when `exporter` does not accept the
    /// destination kind, [`MboxTurboError::TargetExists`] when the target exists and the
    /// policy is [`Overwrite::Refuse`], [`MboxTurboError::Cancelled`] when the token is
    /// cancelled, and whatever staging, extraction or the exporter fails with.
    pub fn run(self, exporter: Box<dyn Exporter>) -> Result<ExportSummary, MboxTurboError> {
        let started = Instant::now();
        let reader = self.pipeline.select(&self.mailbox, self.selection)?;
        let kind = self.destination.kind();
        if !exporter.accepts(kind) {
            return Err(MboxTurboError::UnsupportedDestination {
                kind,
                target: self.destination.path(),
            });
        }
        let schema = self.pipeline.schema();
        let mut run = Run {
            bytes: 0,
            cancel: self.cancel,
            done: 0,
            exporter,
            progress: self.progress,
            reader,
            staged: self.destination.stage(self.overwrite)?,
        };
        run.exporter.begin(&schema, &mut run.staged)?;
        run.drain()?;
        run.exporter.finish(&mut run.staged)?;
        let path = run.staged.commit()?;
        Ok(ExportSummary {
            bytes: run.bytes,
            elapsed: started.elapsed(),
            messages: run.done,
            path,
        })
    }

    /// Exports only the messages `selection` names, in its order.
    #[must_use]
    pub fn selection(mut self, selection: Selection) -> Self {
        self.selection = selection;
        self
    }
}

/// The state of an export in flight; dropping it removes the staged output.
struct Run {
    /// Bytes written so far.
    bytes: u64,
    /// Raised to stop the export.
    cancel: Option<CancelToken>,
    /// Messages written so far.
    done: u64,
    /// The format being written.
    exporter: Box<dyn Exporter>,
    /// Called after each written batch.
    progress: Option<ProgressHook>,
    /// The batches still to write.
    reader: BatchReader,
    /// Where the batches go.
    staged: Staged,
}

impl Run {
    /// An Arrow failure at the first message not yet written.
    fn arrow_error(&self, source: ArrowError) -> MboxTurboError {
        let next = position(self.done);
        MboxTurboError::Arrow {
            positions: next..next,
            source,
        }
    }

    /// Recovers the typed error the batch reader wrapped in an Arrow error.
    fn batch_error(&self, error: ArrowError) -> MboxTurboError {
        let ArrowError::ExternalError(inner) = error else {
            return self.arrow_error(error);
        };
        match inner.downcast::<MboxTurboError>() {
            Ok(typed) => *typed,
            Err(other) => self.arrow_error(ArrowError::ExternalError(other)),
        }
    }

    /// Fails with [`MboxTurboError::Cancelled`] once the token is cancelled.
    fn check_cancelled(&self) -> Result<(), MboxTurboError> {
        let cancelled = self.cancel.as_ref().is_some_and(CancelToken::is_cancelled);
        if cancelled {
            return Err(MboxTurboError::Cancelled {
                target: self.staged.target().map(ToOwned::to_owned),
                written: self.done,
            });
        }
        Ok(())
    }

    /// Writes every batch, checking for cancellation before each one.
    fn drain(&mut self) -> Result<(), MboxTurboError> {
        loop {
            self.check_cancelled()?;
            let Some(batch) = self.reader.next() else {
                return Ok(());
            };
            let decoded = batch.map_err(|error| self.batch_error(error))?;
            self.write(&decoded)?;
        }
    }

    /// Writes one batch, then counts it and reports progress.
    fn write(&mut self, batch: &RecordBatch) -> Result<(), MboxTurboError> {
        let written = self.exporter.write(batch, &mut self.staged)?;
        self.bytes = self.bytes.saturating_add(written);
        self.done = self.done.saturating_add(count(batch.num_rows()));
        if let Some(hook) = &mut self.progress {
            hook(Progress {
                bytes: self.bytes,
                messages: self.done,
                total: count(self.reader.total()),
            });
        }
        Ok(())
    }
}

/// A row count as `u64`, saturating on a platform where `usize` is wider.
#[expect(
    clippy::disallowed_methods,
    reason = "saturating is the right answer on a hypothetical wider usize"
)]
fn count(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// A message count as a position, saturating on a platform where `usize` is narrower.
#[expect(
    clippy::disallowed_methods,
    reason = "saturating is the right answer on a narrower usize"
)]
fn position(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}
