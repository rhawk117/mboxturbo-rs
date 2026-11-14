//! The build path: streaming a mailbox scan into the encoded index file.

use std::io;

use memmap2::Mmap;
use rayon::prelude::*;

use super::format::{Layout, Writer};
use super::{BlockSize, date};
use crate::fingerprint::Fingerprint;
use crate::hint;
use crate::scan::{self, Parallelism};
use crate::width::widen;

/// Encodes the messages whose starts arrive window by window, keeping only one block of starts
/// and dates in memory beside the window in hand.
///
/// A window's last message has no successor yet, so it waits in `carry` until the next window
/// supplies the start its slice runs to.
struct Streamer<'sink> {
    /// The start of the newest message, whose end is not known yet.
    carry: Option<usize>,
    /// The mailbox the starts point into.
    contents: &'sink [u8],
    /// Dates of the messages in `starts`.
    dates: Vec<Option<i64>>,
    /// Whether dating a window uses the rayon pool.
    parallelism: Parallelism,
    /// Messages in a full block.
    per_block: usize,
    /// Starts of the messages not yet pushed to `writer`.
    starts: Vec<u64>,
    /// The index file being written.
    writer: Writer<&'sink mut io::Cursor<Vec<u8>>>,
}

impl Streamer<'_> {
    /// Takes the next window of ascending starts, dating every message whose successor is now
    /// known and pushing each block that fills.
    fn feed(&mut self, window: Vec<usize>) -> io::Result<()> {
        let run: Vec<usize> = self.carry.take().into_iter().chain(window).collect();
        let Some((&last, head)) = run.split_last() else {
            return Ok(());
        };
        self.dates
            .extend(dates_before_last(self.contents, &run, self.parallelism)?);
        self.starts.extend(head.iter().map(|&start| widen(start)));
        self.carry = Some(last);
        self.flush_full()
    }

    /// Dates the newest message to the end of the mailbox and pushes the final block.
    fn finish(mut self) -> io::Result<()> {
        if let Some(last) = self.carry.take() {
            self.dates
                .push(message_date(self.contents, last, self.contents.len())?);
            self.starts.push(widen(last));
        }
        self.flush_full()?;
        if !self.starts.is_empty() {
            self.writer.push(&self.starts, &self.dates)?;
        }
        self.writer.finish().map(|_count| ())
    }

    /// Pushes every full block of `starts` and `dates` and keeps the remainder.
    fn flush_full(&mut self) -> io::Result<()> {
        let starts = self.starts.chunks_exact(self.per_block);
        let dates = self.dates.chunks_exact(self.per_block);
        let full = self.starts.len().saturating_sub(starts.remainder().len());
        for (block_starts, block_dates) in starts.zip(dates) {
            self.writer.push(block_starts, block_dates)?;
        }
        self.starts.drain(..full).for_each(drop);
        self.dates.drain(..full).for_each(drop);
        Ok(())
    }
}

/// Dates in unix seconds of every message of `run` but the last, each running to the next start,
/// `None` for a message without a parsable Date header.
fn dates_before_last(
    contents: &[u8],
    run: &[usize],
    parallelism: Parallelism,
) -> io::Result<Vec<Option<i64>>> {
    let date = |(&start, &end): (&usize, &usize)| message_date(contents, start, end);
    match parallelism {
        Parallelism::Parallel => run
            .par_iter()
            .zip(run.par_iter().skip(1))
            .map(date)
            .collect(),
        Parallelism::Sequential => run.iter().zip(run.iter().skip(1)).map(date).collect(),
    }
}

/// The index file for `contents` with blocks of `block_size.entries()` messages, with its header.
#[expect(
    clippy::expect_used,
    reason = "the scanner's starts ascend below the mailbox length and a file the writer \
              finished for `fingerprint` has a header that parses for `fingerprint`; that is \
              all the writer into a `Vec` refuses"
)]
pub(super) fn encoded(
    contents: &Mmap,
    fingerprint: Fingerprint,
    block_size: BlockSize,
    parallelism: Parallelism,
) -> (Vec<u8>, Layout) {
    hint::sequential(contents);
    let windows = scan::windows(contents, parallelism);
    let streamed = stream(contents, windows, fingerprint, block_size, parallelism);
    hint::normal(contents);
    let bytes = streamed.expect("scanned starts encode");
    let layout = Layout::parse(&bytes, fingerprint).expect("a freshly encoded header parses");
    (bytes, layout)
}

/// Date of the message at `start..end` of `contents`, an error when the range is not inside it.
fn message_date(contents: &[u8], start: usize, end: usize) -> io::Result<Option<i64>> {
    contents
        .get(start..end)
        .map(date::extract)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "a message starts past the end"))
}

/// The index file for the messages whose starts `windows` yields in order, as bytes.
///
/// # Errors
///
/// An error when a start lies past the end of `contents`.
#[expect(
    clippy::too_many_arguments,
    reason = "five inputs against the bound of four: the writer's fingerprint and block shift, \
              the bytes and windows it dates, and the parallelism of that dating are independent, \
              and a struct bundling any two would exist for this private function alone"
)]
pub(super) fn stream<I>(
    contents: &[u8],
    windows: I,
    fingerprint: Fingerprint,
    block_size: BlockSize,
    parallelism: Parallelism,
) -> io::Result<Vec<u8>>
where
    I: IntoIterator<Item = Vec<usize>>,
{
    let mut sink = io::Cursor::new(Vec::new());
    let writer = Writer::new(&mut sink, fingerprint, block_size)?;
    let per_block = block_size.entries();
    let mut streamer = Streamer {
        carry: None,
        contents,
        dates: Vec::new(),
        parallelism,
        per_block,
        starts: Vec::new(),
        writer,
    };
    for window in windows {
        streamer.feed(window)?;
    }
    streamer.finish()?;
    Ok(sink.into_inner())
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::super::tests::dated_mailbox;
    use super::super::{date, format};
    use super::{BlockSize, stream};
    use crate::fingerprint::Fingerprint;
    use crate::scan::{self, Parallelism};
    use crate::width::widen;

    /// `format::encode` over the whole scan, the reference the streaming build must match.
    fn reference(contents: &[u8], fingerprint: Fingerprint, block_size: BlockSize) -> Vec<u8> {
        let starts = scan::find_message_starts(contents);
        let dates: Vec<Option<i64>> = starts
            .iter()
            .enumerate()
            .map(|(position, &start)| {
                let end = starts
                    .get(position.saturating_add(1))
                    .copied()
                    .unwrap_or(contents.len());
                date::extract(&contents[start..end])
            })
            .collect();
        let wide: Vec<u64> = starts.iter().map(|&start| widen(start)).collect();
        format::encode(&wide, &dates, fingerprint, block_size).expect("the reference encodes")
    }

    #[test]
    fn a_build_over_forced_small_windows_matches_the_whole_vector_encoding() {
        let contents = dated_mailbox(10_000);
        let fingerprint = Fingerprint::new(&contents, None);
        for (segment, per_window, shift) in [(4096, 1, 8), (999, 3, 8), (50_000, 2, 5), (1, 7, 1)] {
            let block_size = BlockSize::from_shift(shift).expect("shift is within the range");
            let windows = scan::windows_with(&contents, segment, per_window, Parallelism::Parallel);
            let streamed = stream(
                &contents,
                windows,
                fingerprint,
                block_size,
                Parallelism::Parallel,
            )
            .expect("the streaming build encodes");
            assert_eq!(
                streamed,
                reference(&contents, fingerprint, block_size),
                "segment {segment} x {per_window} windows at shift {shift} equals the reference"
            );
        }
    }

    #[test]
    fn a_block_straddling_a_window_boundary_decodes_to_the_per_position_spans() {
        let contents = dated_mailbox(10_000);
        let fingerprint = Fingerprint::new(&contents, None);
        let windows = scan::windows_with(&contents, 3000, 1, Parallelism::Parallel);
        let bytes = stream(
            &contents,
            windows,
            fingerprint,
            BlockSize::default(),
            Parallelism::Parallel,
        )
        .expect("the build encodes");
        let layout = format::Layout::parse(&bytes, fingerprint).expect("the header parses");
        let starts = scan::find_message_starts(&contents);
        for position in 0..starts.len() {
            let span = layout
                .span(&bytes, position)
                .expect("every position has a span");
            let end = starts
                .get(position.saturating_add(1))
                .copied()
                .unwrap_or(contents.len());
            assert_eq!(
                span,
                starts[position]..end,
                "position {position} decodes its span"
            );
        }
    }

    #[test]
    fn every_streamed_date_equals_the_extractor_including_the_last_message_of_each_window() {
        let contents = dated_mailbox(10_000);
        let fingerprint = Fingerprint::new(&contents, None);
        let windows: Vec<Vec<usize>> =
            scan::windows_with(&contents, 3000, 1, Parallelism::Parallel).collect();
        let bytes = stream(
            &contents,
            windows,
            fingerprint,
            BlockSize::default(),
            Parallelism::Parallel,
        )
        .expect("the build encodes");
        let layout = format::Layout::parse(&bytes, fingerprint).expect("the header parses");
        let starts = scan::find_message_starts(&contents);
        for position in 0..starts.len() {
            let end = starts.get(position.saturating_add(1)).copied();
            let message = &contents[starts[position]..end.unwrap_or(contents.len())];
            assert_eq!(
                layout.date(&bytes, position),
                Some(date::extract(message)),
                "position {position} carries the extractor's date"
            );
        }
    }

    #[test]
    fn an_empty_mailbox_streams_to_the_reference_empty_index() {
        let fingerprint = Fingerprint::new(b"", None);
        let streamed = stream(
            b"",
            scan::windows(b"", Parallelism::Parallel),
            fingerprint,
            BlockSize::default(),
            Parallelism::Parallel,
        )
        .expect("an empty mailbox encodes");
        assert_eq!(
            streamed,
            reference(b"", fingerprint, BlockSize::default()),
            "no messages yield the reference empty file"
        );
    }

    #[test]
    fn a_start_past_the_end_of_the_mailbox_is_invalid_data() {
        let contents = dated_mailbox(10);
        let fingerprint = Fingerprint::new(&contents, None);
        let error = stream(
            &contents,
            [vec![contents.len() + 1]],
            fingerprint,
            BlockSize::default(),
            Parallelism::Sequential,
        )
        .expect_err("a start past the end cannot be dated");
        assert_eq!(
            error.kind(),
            io::ErrorKind::InvalidData,
            "the out-of-range start is reported as invalid data"
        );
    }
}
