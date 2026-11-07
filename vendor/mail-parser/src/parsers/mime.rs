/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use std::borrow::Cow;

use super::MessageStream;

impl<'x> MessageStream<'x> {
    pub fn seek_next_part(&mut self, boundary: &[u8]) -> bool {
        if boundary.is_empty() {
            return false;
        }
        self.checkpoint();
        let start = self.offset();
        let rest = self.bytes(start..self.len());
        match find_delimiter(rest, boundary) {
            Some(dashes) => {
                self.skip_bytes(dashes + 2 + boundary.len());
                true
            }
            None => {
                self.restore();
                false
            }
        }
    }

    pub fn seek_next_part_offset(&mut self, boundary: &[u8]) -> Option<usize> {
        let mut last_ch = b'\n';
        let mut offset_pos = self.offset();
        self.checkpoint();

        while let Some(&ch) = self.next() {
            if ch == b'\n' {
                offset_pos = if last_ch == b'\r' {
                    self.offset() - 2
                } else {
                    self.offset() - 1
                };
            } else if ch == b'-' && last_ch == b'-' && self.try_skip(boundary) {
                return offset_pos.into();
            }

            last_ch = ch;
        }

        self.restore();

        None
    }

    pub fn mime_part(&mut self, boundary: &[u8]) -> (usize, Cow<'x, [u8]>) {
        let start_pos = self.offset();
        self.checkpoint();
        let rest = self.bytes(start_pos..self.len());
        if boundary.is_empty() {
            self.skip_bytes(rest.len());
            return (self.offset(), rest.into());
        }
        match find_delimiter(rest, boundary) {
            Some(dashes) => {
                let end_pos = start_pos + end_before_delimiter(&rest[..dashes]);
                self.skip_bytes(dashes + 2 + boundary.len());
                (end_pos, self.bytes(start_pos..end_pos).into())
            }
            None => {
                self.restore();
                (usize::MAX, rest.into())
            }
        }
    }

    pub fn seek_part_end(&mut self, boundary: Option<&[u8]>) -> (usize, bool) {
        let mut last_ch = b'\n';
        let mut before_last_ch = 0;
        let mut end_pos = self.offset();

        if let Some(boundary) = boundary {
            while let Some(&ch) = self.next() {
                if ch == b'\n' {
                    end_pos = if last_ch == b'\r' {
                        self.offset() - 2
                    } else {
                        self.offset() - 1
                    };
                } else if ch == b'-' && last_ch == b'-' && self.try_skip(boundary) {
                    if before_last_ch != b'\n' {
                        end_pos = self.offset() - boundary.len() - 2;
                    }
                    return (end_pos, true);
                }

                before_last_ch = last_ch;
                last_ch = ch;
            }

            (self.offset(), false)
        } else {
            self.seek_end();
            (self.offset(), true)
        }
    }

    pub fn is_multipart_end(&mut self) -> bool {
        self.checkpoint();

        match (self.next(), self.peek()) {
            (Some(b'\r'), Some(b'\n')) => {
                self.next();
                false
            }
            (Some(b'-'), Some(b'-')) => {
                self.next();
                true
            }
            (Some(b'\n'), _) => false,
            (Some(&a), _) if a.is_ascii_whitespace() => {
                self.skip_crlf();
                false
            }
            _ => {
                self.restore();
                false
            }
        }
    }

    #[inline(always)]
    pub fn skip_crlf(&mut self) {
        while let Some(ch) = self.peek() {
            match ch {
                b'\r' | b' ' | b'\t' => {
                    self.next();
                }
                b'\n' => {
                    self.next();
                    break;
                }
                _ => break,
            }
        }
    }
}

pub(crate) fn find_delimiter(haystack: &[u8], boundary: &[u8]) -> Option<usize> {
    let delimiter = [b"--", boundary].concat();
    memchr::memmem::find(haystack, &delimiter)
}

pub(crate) fn end_before_delimiter(before: &[u8]) -> usize {
    match before {
        [] => 0,
        [.., b'\r', b'\n'] => before.len() - 2,
        [.., b'\n'] => before.len() - 1,
        [..] => before.len(),
    }
}

#[cfg(test)]
mod delimiter_tests {
    use std::borrow::Cow;

    use super::MessageStream;

    impl<'x> MessageStream<'x> {
        fn seek_next_part_scalar(&mut self, boundary: &[u8]) -> bool {
            if !boundary.is_empty() {
                let mut last_ch = 0;

                self.checkpoint();

                while let Some(&ch) = self.next() {
                    if ch == b'-' && last_ch == b'-' && self.try_skip(boundary) {
                        return true;
                    }

                    last_ch = ch;
                }

                self.restore();
            }

            false
        }

        fn mime_part_scalar(&mut self, boundary: &[u8]) -> (usize, Cow<'x, [u8]>) {
            let mut last_ch = b'\n';
            let mut before_last_ch = 0;
            let start_pos = self.offset();
            let mut end_pos = self.offset();

            self.checkpoint();

            while let Some(&ch) = self.next() {
                if ch == b'\n' {
                    end_pos = if last_ch == b'\r' {
                        self.offset() - 2
                    } else {
                        self.offset() - 1
                    };
                } else if ch == b'-'
                    && !boundary.is_empty()
                    && last_ch == b'-'
                    && self.try_skip(boundary)
                {
                    if before_last_ch != b'\n' {
                        end_pos = self.offset() - boundary.len() - 2;
                    }
                    return (end_pos, self.bytes(start_pos..end_pos).into());
                }

                before_last_ch = last_ch;
                last_ch = ch;
            }

            (
                if boundary.is_empty() {
                    self.offset()
                } else {
                    self.restore();
                    usize::MAX
                },
                self.bytes(start_pos..self.len()).into(),
            )
        }

    }

    #[test]
    fn delimiter_scans_agree_with_the_byte_loops() {
        let alphabet: &[u8] = b"ab-\r\n=x";
        let mut state: u64 = 0x2545_F491_4F6C_DD1D;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..200_000 {
            let len = (next() % 24) as usize;
            let mut body: Vec<u8> = (0..len)
                .map(|_| alphabet[(next() % alphabet.len() as u64) as usize])
                .collect();
            if next() % 2 == 0 {
                let at = (next() % (body.len() as u64 + 1)) as usize;
                body.splice(at..at, b"--ab".iter().copied());
            }
            for boundary in [&b"ab"[..], b"", b"-a"] {
                let mut fast = MessageStream::new(&body);
                let mut slow = MessageStream::new(&body);
                let expected: (usize, Cow<'_, [u8]>) = slow.mime_part_scalar(boundary);
                assert_eq!(fast.mime_part(boundary), expected, "mime_part {:?}", String::from_utf8_lossy(&body));
                assert_eq!(fast.offset(), slow.offset(), "mime_part offset {:?}", String::from_utf8_lossy(&body));
                let mut fast = MessageStream::new(&body);
                let mut slow = MessageStream::new(&body);
                assert_eq!(fast.seek_next_part(boundary), slow.seek_next_part_scalar(boundary), "seek {:?}", String::from_utf8_lossy(&body));
                assert_eq!(fast.offset(), slow.offset(), "seek offset {:?}", String::from_utf8_lossy(&body));
            }
        }
    }
}
