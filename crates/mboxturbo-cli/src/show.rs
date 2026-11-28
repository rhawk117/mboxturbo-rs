//! The `show` subcommand: writes one message's stored bytes to standard output.

use std::borrow::Cow;
use std::io::{self, IsTerminal as _, Write as _};
use std::path::PathBuf;

use clap::Args;
use mboxturbo::MboxTurboError;

use crate::events::Report;
use crate::failure::{self, Failure};
use crate::open::open;
use crate::progress::{self, Feedback};

/// The arguments of `mboxturbo show`.
#[derive(Debug, Args)]
pub(crate) struct ShowArgs {
    /// Keep the message index in this file instead of beside the mailbox.
    #[arg(long, value_name = "PATH")]
    index: Option<PathBuf>,
    /// The mbox file to read.
    mailbox: PathBuf,
    /// The 0-based position of the message.
    position: usize,
    /// Write the stored bytes unchanged even when standard output is a terminal.
    #[arg(long)]
    raw: bool,
}

/// Where the message bytes go, which decides whether control bytes are made visible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Target {
    /// A terminal that would act on control bytes: they are written as visible escapes.
    Terminal,
    /// A pipe, a file, or any target that was asked for the exact bytes.
    Verbatim,
}

/// The bytes to write for `raw` on `target`.
///
/// A [`Target::Verbatim`] target gets `raw` borrowed unchanged. A [`Target::Terminal`] target gets
/// ESC, DEL and every C0 control byte except tab, line feed and carriage return, every C1 control
/// character (U+0080 to U+009F, as its UTF-8 bytes) and every byte that is not part of valid UTF-8
/// as `\xNN` (lower case hex, one escape per byte); all other text is unchanged.
fn render(raw: &[u8], target: Target) -> Cow<'_, [u8]> {
    if target == Target::Verbatim {
        return Cow::Borrowed(raw);
    }
    let mut out = Vec::with_capacity(raw.len());
    for chunk in raw.utf8_chunks() {
        chunk
            .valid()
            .chars()
            .for_each(|character| push_character(&mut out, character));
        chunk
            .invalid()
            .iter()
            .for_each(|&byte| push_escape(&mut out, byte));
    }
    Cow::Owned(out)
}

/// Appends `character` to `out`, as one escape per UTF-8 byte when a terminal could act on it.
fn push_character(out: &mut Vec<u8>, character: char) {
    let mut buffer = [0_u8; 4];
    let bytes = character.encode_utf8(&mut buffer).as_bytes();
    if is_dangerous(character) {
        for &byte in bytes {
            push_escape(out, byte);
        }
    } else {
        out.extend_from_slice(bytes);
    }
}

/// Whether a terminal could act on `character`: DEL, a C0 control other than tab, LF and CR, or a
/// C1 control.
const fn is_dangerous(character: char) -> bool {
    matches!(
        character,
        '\0'..='\x08' | '\x0b' | '\x0c' | '\x0e'..='\x1f' | '\x7f'..='\u{9f}'
    )
}

/// Appends `byte` to `out` as a `\xNN` escape with lower case hex.
fn push_escape(out: &mut Vec<u8>, byte: u8) {
    out.extend_from_slice(format!("\\x{byte:02x}").as_bytes());
}

/// Runs the `show` subcommand: one lookup after the mailbox is open.
///
/// # Errors
///
/// A [`Failure::Usage`] for `--json`, which cannot share standard output with the message, and a
/// [`Failure::Core`] for a position at or past the message count, for everything opening the
/// mailbox refuses, and for a write to standard output that fails.
pub(crate) fn run(args: &ShowArgs, report: Report, feedback: Feedback) -> Result<(), Failure> {
    if report == Report::Events {
        return Err(Failure::Usage(
            "--json cannot be used with `show`: standard output carries the message".to_owned(),
        ));
    }
    let mailbox = open(&args.mailbox, args.index.as_deref())?;
    progress::note_origin(feedback, mailbox.index_origin()).map_err(failure::stderr_failure)?;
    let Some(raw) = mailbox.raw(args.position) else {
        return Err(Failure::other(Box::new(
            MboxTurboError::PositionOutOfRange {
                position: args.position,
                len: mailbox.len(),
            },
        )));
    };
    let mut stdout = io::stdout().lock();
    let target = if args.raw || !stdout.is_terminal() {
        Target::Verbatim
    } else {
        Target::Terminal
    };
    stdout
        .write_all(&render(raw, target))
        .map_err(failure::stdout_failure)?;
    stdout.flush().map_err(failure::stdout_failure)
}

#[cfg(test)]
mod tests {
    use super::{Target, render};

    #[test]
    fn a_terminal_gets_no_escape_or_other_control_byte_from_an_osc_52_message() {
        let hostile = b"Subject: x\n\n\x1b]52;c;aGk=\x07\x7f\x00\x08\x0b\x0c\x1f done\n";
        let shown = render(hostile, Target::Terminal);
        assert_eq!(
            shown.as_ref(),
            b"Subject: x\n\n\\x1b]52;c;aGk=\\x07\\x7f\\x00\\x08\\x0b\\x0c\\x1f done\n".as_slice(),
            "ESC, BEL, DEL and the other C0 bytes become visible escapes"
        );
        assert!(
            shown
                .iter()
                .all(|&byte| byte == b'\n' || (0x20..0x7F).contains(&byte)),
            "no control byte survives except line feed"
        );
    }

    #[test]
    fn a_terminal_keeps_tab_line_feed_carriage_return_and_non_ascii_bytes() {
        let text = "a\tb\r\nc\u{e9}\u{1f600}\n".as_bytes();
        assert_eq!(
            render(text, Target::Terminal).as_ref(),
            text,
            "tab, LF, CR and UTF-8 pass through"
        );
    }

    #[test]
    fn a_terminal_escapes_c1_controls_and_invalid_bytes() {
        let hostile = b"a\xc2\x9b31m \x9b \xff\xc3 b\xc2\x80\xc2\x9f\xc2\xa0\n";
        assert_eq!(
            render(hostile, Target::Terminal).as_ref(),
            b"a\\xc2\\x9b31m \\x9b \\xff\\xc3 b\\xc2\\x80\\xc2\\x9f\xc2\xa0\n".as_slice(),
            "encoded U+009B, U+0080 and U+009F and every invalid byte become escapes; U+00A0 stays"
        );
    }

    #[test]
    fn a_terminal_keeps_valid_non_ascii_text_unchanged() {
        let text = "caf\u{e9} \u{4e2d}\u{6587} \u{1f600} \u{a0}\u{ff}\n".as_bytes();
        assert_eq!(
            render(text, Target::Terminal).as_ref(),
            text,
            "accented Latin, CJK and emoji pass through"
        );
    }

    #[test]
    fn a_verbatim_target_gets_every_stored_byte() {
        let every: Vec<u8> = (0..=u8::MAX).collect();
        assert_eq!(
            render(&every, Target::Verbatim).as_ref(),
            every.as_slice(),
            "a pipe or --raw sees the exact bytes"
        );
    }
}
