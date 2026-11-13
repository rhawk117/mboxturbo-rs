//! Block frame-of-reference codec: a block stores each value as its distance from the block's
//! minimum, packed into the fewest bits that hold the largest distance, so one value is read
//! from at most nine payload bytes and a checksummed directory entry guards the block.

use std::iter::repeat_n;

use xxhash_rust::xxh3::xxh3_64;

/// Flag bit of a dates block: its all-ones code means "no date".
pub(crate) const MISSING: u8 = 1;
/// Widest code a block can hold, in bits.
const MAX_WIDTH: u8 = 64;
/// Widest code width at which one 8-byte load holds two adjacent codes, whatever bit of its first
/// byte they start at.
const PAIR_WIDTH: u8 = 28;
/// Widest code an 8-byte load holds at any bit shift within its first byte.
const WORD_WIDTH: u8 = 57;
/// Bytes a single code can touch: up to 64 bits starting at a bit offset of up to 7.
const WINDOW: usize = 9;

/// Fixed-size directory entry of one block; the payload lives elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Block {
    /// Block minimum; a dates block holds an `i64`'s little-endian bits here.
    pub base: u64,
    /// `xxh3_64` over the base, width and flags bytes, then the payload.
    pub checksum: u64,
    /// Flag bits; only [`MISSING`] is defined.
    pub flags: u8,
    /// Bits per stored code, 0 to 64; zero means every value equals the base.
    pub width: u8,
}

/// Base, width and flags of a block: everything a read needs from its entry, without the checksum
/// that only matters until the block is verified.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Frame {
    /// Block minimum, as `u64` bits.
    pub base: u64,
    /// Flag bits for the entry.
    pub flags: u8,
    /// Bits per stored code.
    pub width: u8,
}

impl Block {
    /// The fields a read needs.
    pub(crate) const fn frame(&self) -> Frame {
        Frame {
            base: self.base,
            flags: self.flags,
            width: self.width,
        }
    }
}

impl Frame {
    /// Code at `index`, or `None` when the frame or the payload cannot hold it.
    #[inline]
    fn code(&self, payload: &[u8], index: usize) -> Option<u64> {
        let bit = index.checked_mul(usize::from(self.width))?;
        read_code(payload, bit, self.width)
    }

    /// Codes at `index` and `index + 1`, from one 16-byte load when both lie in it, else read
    /// one at a time; `None` when either is past the payload or the width exceeds 64.
    #[inline]
    fn code_pair(&self, payload: &[u8], index: usize) -> Option<(u64, u64)> {
        let width = usize::from(self.width);
        let bit = index.checked_mul(width)?;
        let next = bit.checked_add(width)?;
        if self.width > MAX_WIDTH || next.checked_add(width)?.div_ceil(8) > payload.len() {
            return None;
        }
        load_pair(payload, 0, bit, self.width).or_else(|| {
            Some((
                read_code(payload, bit, self.width)?,
                read_code(payload, next, self.width)?,
            ))
        })
    }

    /// Date at `index` of a dates block, as [`date`] answers it.
    #[expect(
        clippy::option_option,
        reason = "the outer `None` is a refused block, the inner one a message with no date"
    )]
    pub(crate) fn date(&self, payload: &[u8], index: usize) -> Option<Option<i64>> {
        if self.flags & !MISSING != 0 || (self.flags == MISSING && self.width == 0) {
            return None;
        }
        let raw = self.code(payload, index)?;
        if self.flags == MISSING && raw == mask(self.width) {
            return Some(None);
        }
        signed_of(self.base).checked_add_unsigned(raw).map(Some)
    }

    /// Start at `index` of a starts block, as [`start`] answers it.
    #[inline]
    pub(crate) fn start(&self, payload: &[u8], index: usize) -> Option<u64> {
        if self.flags != 0 {
            return None;
        }
        self.base.checked_add(self.code(payload, index)?)
    }

    /// Start at `index` of a starts block whose payload begins at byte `payload` of `bytes`,
    /// read with one unaligned 8-byte load. The caller guarantees that `index` lies inside the
    /// block, whose payload was checked to cover it; the load may run past the payload into the
    /// bytes that follow it, whose bits the mask drops. `None`, for the caller to read the
    /// start the long way, for a flagged block, a width a single load cannot hold, or a load
    /// past the end of `bytes`.
    #[inline]
    pub(crate) fn start_at(&self, bytes: &[u8], payload: usize, index: usize) -> Option<u64> {
        if self.flags != 0 || self.width > WORD_WIDTH {
            return None;
        }
        let (byte, shift) = split_bit(index.checked_mul(usize::from(self.width))?)?;
        let word = bytes
            .get(payload.checked_add(byte)?..)?
            .first_chunk::<8>()?;
        let code = u64::from_le_bytes(*word).checked_shr(shift)? & mask(self.width);
        self.base.checked_add(code)
    }

    /// Starts at `index` and `index + 1` of a starts block, each as [`Frame::start`] answers it,
    /// `None` when either is `None`.
    #[inline]
    pub(crate) fn start_pair(&self, payload: &[u8], index: usize) -> Option<(u64, u64)> {
        if self.flags != 0 {
            return None;
        }
        let (first, second) = self.code_pair(payload, index)?;
        Some((
            self.base.checked_add(first)?,
            self.base.checked_add(second)?,
        ))
    }

    /// Starts at `index` and `index + 1` of a starts block whose payload begins at byte
    /// `payload` of `bytes`, both read from one unaligned 16-byte load under the precondition of
    /// [`Frame::start_at`] for `index + 1`, and refused as it refuses.
    #[inline]
    pub(crate) fn start_pair_at(
        &self,
        bytes: &[u8],
        payload: usize,
        index: usize,
    ) -> Option<(u64, u64)> {
        if self.flags != 0 || self.width > WORD_WIDTH {
            return None;
        }
        let bit = index.checked_mul(usize::from(self.width))?;
        let (first, second) = load_pair(bytes, payload, bit, self.width)?;
        Some((
            self.base.checked_add(first)?,
            self.base.checked_add(second)?,
        ))
    }
}

/// The `width`-bit codes at bit offset `bit` of the payload that begins at byte `payload` of
/// `bytes`, and right after it, from one unaligned 16-byte load; `None` when the load would
/// leave `bytes` or the two codes do not both lie in it. Both start `bit % 8` bits into the load.
#[inline]
fn load_pair(bytes: &[u8], payload: usize, bit: usize, width: u8) -> Option<(u64, u64)> {
    let (byte, shift) = split_bit(bit)?;
    let chunk = bytes
        .get(payload.checked_add(byte)?..)?
        .first_chunk::<16>()?;
    let (first, second) = adjacent(chunk, shift, width)?;
    let low = mask(width);
    Some((first & low, second & low))
}

/// The bits of the two adjacent `width`-bit codes that start `shift` bits into `chunk`, each
/// still to be masked to `width` bits; from its first eight bytes alone when both fit in them, and
/// `None` when the two codes do not both lie in the 16 bytes.
#[inline]
fn adjacent(chunk: &[u8; 16], shift: u32, width: u8) -> Option<(u64, u64)> {
    if width <= PAIR_WIDTH {
        let word = u64::from_le_bytes(*chunk.first_chunk::<8>()?).checked_shr(shift)?;
        return Some((word, word.checked_shr(u32::from(width))?));
    }
    if shift.checked_add(u32::from(width).checked_mul(2)?)? > u128::BITS {
        return None;
    }
    let wide = u128::from_le_bytes(*chunk).checked_shr(shift)?;
    Some((
        low_word(wide),
        low_word(wide.checked_shr(u32::from(width))?),
    ))
}

/// The low 64 bits of `value`.
const fn low_word(value: u128) -> u64 {
    let [b0, b1, b2, b3, b4, b5, b6, b7, ..] = value.to_le_bytes();
    u64::from_le_bytes([b0, b1, b2, b3, b4, b5, b6, b7])
}

/// Bits needed to store `range`; zero for zero.
fn bit_width(range: u64) -> u8 {
    let bits = u64::BITS.saturating_sub(range.leading_zeros());
    let Ok(width) = u8::try_from(bits) else {
        return MAX_WIDTH;
    };
    width
}

/// Mask of the low `width` bits; zero for width 0 or any width above 64.
fn mask(width: u8) -> u64 {
    u64::MAX
        .checked_shr(u32::from(MAX_WIDTH.saturating_sub(width)))
        .unwrap_or(0)
}

/// Payload bytes needed for `count` codes of `width` bits, or `None` when `width` exceeds 64 or
/// the size overflows.
pub(crate) fn payload_len(count: usize, width: u8) -> Option<usize> {
    if width > MAX_WIDTH {
        return None;
    }
    let bits = count.checked_mul(usize::from(width))?;
    Some(bits.div_ceil(8))
}

/// Splits a bit offset into its byte offset and its bit shift within that byte.
fn split_bit(bit: usize) -> Option<(usize, u32)> {
    let byte = bit.checked_div(8)?;
    let Ok(shift) = u32::try_from(bit.checked_rem(8)?) else {
        return None;
    };
    Some((byte, shift))
}

/// ORs the `width`-bit `code` into `buf` at bit offset `bit`; `None` when the range lies outside
/// `buf`. `buf` is zero where the code goes, so the OR is a store.
fn put(buf: &mut [u8], bit: usize, width: u8, code: u64) -> Option<()> {
    let end = bit.checked_add(usize::from(width))?;
    if end.div_ceil(8) > buf.len() {
        return None;
    }
    let (byte, shift) = split_bit(bit)?;
    let spread = u128::from(code & mask(width)).checked_shl(shift)?;
    let dst = buf.get_mut(byte..)?;
    for (out, bits) in dst.iter_mut().zip(spread.to_le_bytes()) {
        *out |= bits;
    }
    Some(())
}

/// Reads the `width`-bit code at bit offset `bit` from a 16-byte load, or from a zero-padded
/// window near the end of `payload`; only the code's own bits reach the answer. `None` when `width`
/// exceeds 64 or the bits are not all in `payload`.
#[inline]
fn read_code(payload: &[u8], bit: usize, width: u8) -> Option<u64> {
    if width > MAX_WIDTH {
        return None;
    }
    let end = bit.checked_add(usize::from(width))?;
    if end.div_ceil(8) > payload.len() {
        return None;
    }
    if width == 0 {
        return Some(0);
    }
    let (byte, shift) = split_bit(bit)?;
    let rest = payload.get(byte..)?;
    let wide = rest
        .first_chunk::<16>()
        .map_or_else(|| padded(rest), |chunk| u128::from_le_bytes(*chunk));
    Some(low_word(wide.checked_shr(shift)?) & mask(width))
}

/// The first nine bytes of `bytes`, fewer when it is shorter, zero-padded to a `u128`: every
/// byte a code starting in the first of them can touch.
fn padded(bytes: &[u8]) -> u128 {
    let mut window = [0_u8; 16];
    for (dst, src) in window.iter_mut().zip(bytes.iter().take(WINDOW)) {
        *dst = *src;
    }
    u128::from_le_bytes(window)
}

/// Packs `count` codes of `width` bits, little-endian bit order; empty when a code does not fit,
/// which a caller that sized `width` from the codes never sees.
fn pack(codes: impl Iterator<Item = u64>, count: usize, width: u8) -> Vec<u8> {
    let Some(len) = payload_len(count, width) else {
        return Vec::new();
    };
    let mut buf: Vec<u8> = repeat_n(0_u8, len).collect();
    let step = usize::from(width);
    let packed = codes
        .enumerate()
        .try_for_each(|(index, code)| put(&mut buf, index.checked_mul(step)?, width, code));
    if packed.is_none() {
        buf.clear();
    }
    buf
}

/// Checksum of an entry's base, width and flags bytes followed by its payload.
fn checksum(base: u64, width: u8, flags: u8, payload: &[u8]) -> u64 {
    let mut bytes = Vec::with_capacity(payload.len().saturating_add(10));
    bytes.extend_from_slice(&base.to_le_bytes());
    bytes.push(width);
    bytes.push(flags);
    bytes.extend_from_slice(payload);
    xxh3_64(&bytes)
}

/// Packs the codes, appends the payload to `out` and seals the entry with its checksum.
fn seal(layout: Frame, count: usize, codes: impl Iterator<Item = u64>, out: &mut Vec<u8>) -> Block {
    let payload = pack(codes, count, layout.width);
    out.extend_from_slice(&payload);
    Block {
        base: layout.base,
        checksum: checksum(layout.base, layout.width, layout.flags, &payload),
        flags: layout.flags,
        width: layout.width,
    }
}

/// Appends the payload of `values` (any order; sorted starts give the smallest width) to `out`
/// and returns the entry.
pub(crate) fn encode_starts(values: &[u64], out: &mut Vec<u8>) -> Block {
    let base = values.iter().copied().min().unwrap_or(0);
    let top = values.iter().copied().max().unwrap_or(0);
    let width = bit_width(top.saturating_sub(base));
    let codes = values.iter().map(|value| value.saturating_sub(base));
    seal(
        Frame {
            base,
            flags: 0,
            width,
        },
        values.len(),
        codes,
        out,
    )
}

/// Moves an `i64`'s bits into a `u64`.
const fn bits_of(value: i64) -> u64 {
    u64::from_le_bytes(value.to_le_bytes())
}

/// Moves a `u64`'s bits into an `i64`.
const fn signed_of(bits: u64) -> i64 {
    i64::from_le_bytes(bits.to_le_bytes())
}

/// Minimum and maximum of the present dates, or `None` when there are none.
fn dated_span(values: &[Option<i64>]) -> Option<(i64, i64)> {
    let mut present = values.iter().copied().flatten();
    let first = present.next()?;
    Some(present.fold((first, first), |(low, high), value| {
        (low.min(value), high.max(value))
    }))
}

/// Chooses base, width and flags for a dates block: the "no date" sentinel is used only when a
/// date is missing; its width holds `span + 1`, so the all-ones code exceeds every real delta.
/// A block with no present date keeps one bit per code, all ones. Returns `None` when a date is
/// missing and the present dates span the whole `i64` range, which leaves no code for the sentinel.
fn date_layout(values: &[Option<i64>]) -> Option<Frame> {
    let (min, max) = dated_span(values).unwrap_or((0, 0));
    let range = max.abs_diff(min);
    if !values.contains(&None) {
        return Some(Frame {
            base: bits_of(min),
            flags: 0,
            width: bit_width(range),
        });
    }
    // The all-ones code of a width-w block is 2^w - 1, so it sits above every real delta (at most
    // `range`) once w holds `range + 1`.
    let width = range.checked_add(1).map(bit_width)?;
    Some(Frame {
        base: bits_of(min),
        flags: MISSING,
        width,
    })
}

/// Appends the payload of `values` (`None` meaning "no date") to `out` and returns the entry, or
/// `None` when `values` holds a missing date and the present dates span the whole `i64` range:
/// no code is left to mark the missing date, and `out` is untouched.
pub(crate) fn encode_dates(values: &[Option<i64>], out: &mut Vec<u8>) -> Option<Block> {
    let layout = date_layout(values)?;
    let origin = signed_of(layout.base);
    let sentinel = if layout.flags & MISSING != 0 {
        mask(layout.width)
    } else {
        0
    };
    let codes = values
        .iter()
        .map(|value| value.map_or(sentinel, |date| date.abs_diff(origin)));
    Some(seal(layout, values.len(), codes, out))
}

/// Whether `payload` and the entry's fields match the entry's checksum.
pub(crate) fn verify(block: &Block, payload: &[u8]) -> bool {
    checksum(block.base, block.width, block.flags, payload) == block.checksum
}

/// Start at `index` of a starts block, or `None` for an unknown flag, a width above 64, or an
/// index the payload does not cover. An all-equal block (width 0) answers any index with its base.
#[cfg(test)]
pub(crate) fn start(block: &Block, payload: &[u8], index: usize) -> Option<u64> {
    block.frame().start(payload, index)
}

/// Date at `index` of a dates block, `Some(None)` for "no date", or `None` for an unknown flag, a
/// width above 64, a sentinel block of width 0, or an index the payload does not cover.
#[cfg(test)]
#[expect(
    clippy::option_option,
    reason = "the outer `None` is a refused block, the inner one a message with no date"
)]
pub(crate) fn date(block: &Block, payload: &[u8], index: usize) -> Option<Option<i64>> {
    block.frame().date(payload, index)
}

/// Replaces the contents of `into` with the first `count` starts of a starts block, read in one
/// pass over `payload`. `None`, with `into` unspecified, for an unknown flag, a width above 64, a
/// payload shorter than `count` codes, or a start past `u64::MAX`; each value equals what
/// [`start`] answers for its index.
pub(crate) fn starts(
    frame: &Frame,
    payload: &[u8],
    count: usize,
    into: &mut Vec<u64>,
) -> Option<()> {
    if frame.flags != 0 || payload_len(count, frame.width)? > payload.len() {
        return None;
    }
    into.clear();
    into.resize(count, 0);
    if frame.width > WORD_WIDTH {
        return wide_starts(frame, payload, into);
    }
    let step = usize::from(frame.width);
    let low = mask(frame.width);
    let mut bit = 0_usize;
    for slot in into.iter_mut() {
        let (byte, shift) = split_bit(bit)?;
        let code = match payload.get(byte..).and_then(<[u8]>::first_chunk::<8>) {
            Some(word) => u64::from_le_bytes(*word).checked_shr(shift)? & low,
            None => read_code(payload, bit, frame.width)?,
        };
        *slot = frame.base.checked_add(code)?;
        bit = bit.checked_add(step)?;
    }
    Some(())
}

/// Fills `into` with the starts of a block whose codes are too wide for one 8-byte load, one
/// [`read_code`] at a time.
#[cold]
fn wide_starts(frame: &Frame, payload: &[u8], into: &mut [u64]) -> Option<()> {
    let step = usize::from(frame.width);
    let mut bit = 0_usize;
    for slot in into.iter_mut() {
        *slot = frame
            .base
            .checked_add(read_code(payload, bit, frame.width)?)?;
        bit = bit.checked_add(step)?;
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use proptest::collection::vec;
    use proptest::prelude::*;

    use super::*;

    /// Largest block the format stores.
    const BLOCK: usize = 256;

    /// A block, its payload and every value read back through the public readers.
    struct Decoded<T> {
        /// Directory entry of the block.
        block: Block,
        /// Packed payload of the block.
        payload: Vec<u8>,
        /// One read per encoded value.
        values: Vec<Option<T>>,
    }

    fn decode_starts(values: &[u64]) -> Decoded<u64> {
        let mut payload = Vec::new();
        let block = encode_starts(values, &mut payload);
        let read = (0..values.len())
            .map(|index| start(&block, &payload, index))
            .collect();
        Decoded {
            block,
            payload,
            values: read,
        }
    }

    fn decode_dates(values: &[Option<i64>]) -> Decoded<Option<i64>> {
        let mut payload = Vec::new();
        let block = encode_dates(values, &mut payload)
            .expect("the block's present dates leave a code free for a missing date");
        let read = (0..values.len())
            .map(|index| date(&block, &payload, index))
            .collect();
        Decoded {
            block,
            payload,
            values: read,
        }
    }

    fn some<T>(values: &[T]) -> Vec<Option<T>>
    where
        T: Copy,
    {
        values.iter().copied().map(Some).collect()
    }

    fn sorted(mut values: Vec<u64>) -> Vec<u64> {
        values.sort_unstable();
        values
    }

    /// Payload bytes that hold the code at `index`.
    fn touched(block: &Block, index: usize) -> Range<usize> {
        let width = usize::from(block.width);
        let first = index.saturating_mul(width);
        first.checked_div(8).unwrap()..first.saturating_add(width).div_ceil(8)
    }

    #[test]
    fn a_missing_date_in_a_full_range_block_is_refused() {
        let mut payload = Vec::new();
        let block = encode_dates(&[None, Some(i64::MIN), Some(i64::MAX)], &mut payload);
        assert!(
            block.is_none(),
            "no code is left to mark the missing date beside a full-range span"
        );
        assert!(payload.is_empty(), "a refused block appends nothing");
    }

    #[test]
    fn spans_under_two_to_the_22_use_at_most_22_bits() {
        let values: Vec<u64> = (0..256_u64)
            .map(|index| index.saturating_mul(0x4000))
            .collect();
        let decoded = decode_starts(&values);
        assert!(
            decoded.block.width <= 22,
            "the width is the bits of the range"
        );
        assert_eq!(decoded.payload.len(), 704, "22 bits times 256 values");
        assert_eq!(decoded.values, some(&values), "every start comes back");
    }

    #[test]
    fn equal_values_have_an_empty_payload() {
        let starts = decode_starts(&[9_u64; 40]);
        assert_eq!(
            (starts.block.width, starts.payload.len()),
            (0, 0),
            "no bits are needed"
        );
        assert_eq!(starts.values, some(&[9_u64; 40]), "equal values read back");
        let dates = decode_dates(&[Some(0); 5]);
        assert_eq!(
            (dates.block.width, dates.payload.len()),
            (0, 0),
            "all-epoch dates are equal values"
        );
        assert_eq!(
            dates.values,
            some(&[Some(0); 5]),
            "all-epoch dates read back"
        );
    }

    #[test]
    fn missing_dates_use_the_sentinel_and_keep_the_width_small() {
        let values = [None, Some(1_700_000_000), None, Some(1_700_000_300), None];
        let decoded = decode_dates(&values);
        assert_eq!(
            decoded.block.flags, MISSING,
            "a missing date takes the sentinel"
        );
        assert_eq!(
            decoded.block.width, 9,
            "a span of 300 needs 301 codes, one more than the span, and that fits in nine bits"
        );
        assert_eq!(
            decoded.values,
            some(&values),
            "missing dates come back missing"
        );
    }

    #[test]
    fn a_missing_date_beside_a_full_width_span_uses_the_sentinel_at_width_64() {
        let values = [Some(i64::MIN), Some(-1), None];
        let decoded = decode_dates(&values);
        assert_eq!(
            decoded.block.flags, MISSING,
            "a missing date takes the sentinel"
        );
        assert_eq!(
            decoded.block.width, 64,
            "a span of 2^63 - 1 needs 2^63 codes, which takes 64 bits"
        );
        assert!(
            verify(&decoded.block, &decoded.payload),
            "the checksum matches the width-64 payload"
        );
        assert_eq!(
            decoded.values,
            some(&values),
            "all three dates come back, the missing one included"
        );
    }

    #[test]
    fn a_one_pass_decode_refuses_a_payload_short_of_its_count() {
        let values = [10, 300, 70_000];
        let decoded = decode_starts(&values);
        let mut all = Vec::new();
        assert_eq!(
            starts(&decoded.block.frame(), &decoded.payload[..1], 3, &mut all),
            None,
            "three 17-bit codes need seven bytes"
        );
    }

    #[test]
    fn dates_without_a_missing_one_need_no_sentinel() {
        let values = [Some(-5), Some(0), Some(7)];
        let decoded = decode_dates(&values);
        assert_eq!(decoded.block.flags, 0, "no date is missing");
        assert_eq!(decoded.values, some(&values), "dates come back");
    }

    #[test]
    fn a_block_mixing_missing_epoch_and_other_dates_keeps_each_apart() {
        let values = [
            None,
            Some(0),
            Some(-86_400),
            None,
            Some(1_704_110_460),
            Some(0),
        ];
        let decoded = decode_dates(&values);
        assert_eq!(
            decoded.block.flags, MISSING,
            "a missing date takes the sentinel"
        );
        assert_eq!(
            decoded.values,
            some(&values),
            "a real epoch date reads back as Some(0), apart from a missing one"
        );
    }

    #[test]
    fn a_block_of_only_missing_dates_reads_back_missing() {
        let values = [None; 4];
        let decoded = decode_dates(&values);
        assert_eq!(
            decoded.block.flags, MISSING,
            "every date takes the sentinel"
        );
        assert_eq!(
            decoded.values,
            some(&values),
            "every date reads back missing"
        );
    }

    #[test]
    fn extremes_roundtrip() {
        let starts = decode_starts(&[0, u64::MAX]);
        assert_eq!(
            starts.values,
            some(&[0, u64::MAX]),
            "a 64-bit span survives"
        );
        let values = [Some(i64::MIN), Some(0), Some(i64::MAX)];
        let dates = decode_dates(&values);
        assert_eq!(dates.values, some(&values), "the full i64 range survives");
    }

    #[test]
    fn corrupt_entries_and_short_payloads_return_none() {
        let mut payload = Vec::new();
        let block = encode_starts(&[3, 90, 500], &mut payload);
        let wide = Block { width: 65, ..block };
        assert_eq!(start(&wide, &payload, 0), None, "width above 64");
        let flagged = Block { flags: 2, ..block };
        assert_eq!(start(&flagged, &payload, 0), None, "unknown flag");
        assert_eq!(date(&flagged, &payload, 0), None, "unknown flag on dates");
    }

    #[test]
    fn short_payloads_and_bad_indexes_return_none() {
        let mut payload = Vec::new();
        let block = encode_starts(&[3, 90, 500], &mut payload);
        assert_eq!(start(&block, &payload[..1], 2), None, "short payload");
        assert_eq!(start(&block, &payload, usize::MAX), None, "index overflow");
        assert_eq!(
            start(&block, &payload, 1000),
            None,
            "index past the payload"
        );
        assert_eq!(payload_len(1, 65), None, "payload_len refuses width 65");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn starts_roundtrip_for_any_block(values in vec(any::<u64>(), 0..=BLOCK)) {
            let ordered = sorted(values);
            let decoded = decode_starts(&ordered);
            prop_assert_eq!(decoded.values, some(&ordered), "decoding returns the encoded starts");
            prop_assert!(verify(&decoded.block, &decoded.payload), "a fresh block verifies");
        }

        #[test]
        fn narrow_starts_roundtrip(base in any::<u32>(), gaps in vec(0_u64..5000, 0..=BLOCK)) {
            let mut total = u64::from(base);
            let values: Vec<u64> = gaps
                .iter()
                .map(|gap| {
                    total = total.saturating_add(*gap);
                    total
                })
                .collect();
            let decoded = decode_starts(&values);
            prop_assert_eq!(decoded.values, some(&values), "decoding returns the encoded starts");
        }

        #[test]
        fn dates_roundtrip_for_any_block(
            values in vec(
                prop_oneof![
                    Just(None),
                    Just(Some(0_i64)),
                    any::<i64>().prop_map(Some),
                    (1_i64..100_000).prop_map(Some),
                    (-500_i64..500).prop_map(Some),
                ],
                0..=BLOCK,
            )
        ) {
            let full_span = dated_span(&values)
                .is_some_and(|(low, high)| high.abs_diff(low) == u64::MAX);
            if values.contains(&None) && full_span {
                prop_assert!(
                    encode_dates(&values, &mut Vec::new()).is_none(),
                    "a missing date in a full-range block is refused"
                );
                return Ok(());
            }
            let decoded = decode_dates(&values);
            prop_assert_eq!(decoded.values, some(&values), "decoding returns the encoded dates");
            prop_assert!(verify(&decoded.block, &decoded.payload), "a fresh block verifies");
        }

        #[test]
        fn a_one_pass_decode_matches_every_single_read(values in vec(any::<u64>(), 0..=BLOCK)) {
            let ordered = sorted(values);
            let decoded = decode_starts(&ordered);
            let mut all = vec![7];
            let outcome = starts(&decoded.block.frame(), &decoded.payload, ordered.len(), &mut all);
            prop_assert_eq!(outcome, Some(()), "a sound block decodes");
            prop_assert_eq!(
                all.into_iter().map(Some).collect::<Vec<_>>(),
                decoded.values,
                "the one-pass decode replaces the vector with what start reads per index"
            );
        }

        #[test]
        fn a_pair_read_matches_two_single_reads(
            values in vec(any::<u64>(), 2..=BLOCK),
            pick in any::<usize>(),
        ) {
            let ordered = sorted(values);
            let decoded = decode_starts(&ordered);
            let index = pick.checked_rem(ordered.len().saturating_sub(1)).unwrap();
            let frame = decoded.block.frame();
            prop_assert_eq!(
                frame.start_pair(&decoded.payload, index),
                Some((ordered[index], ordered[index.saturating_add(1)])),
                "one load answers both neighbours, at every width and near the payload end"
            );
        }

        #[test]
        fn a_lookup_reads_only_its_own_bytes(
            values in vec(0_u64..0x0100_0000_0000, 1..=BLOCK),
            pick in any::<usize>(),
        ) {
            let ordered = sorted(values);
            let decoded = decode_starts(&ordered);
            let index = pick.checked_rem(ordered.len()).unwrap();
            let range = touched(&decoded.block, index);
            let mut garbled = vec![0xA5_u8; decoded.payload.len()];
            garbled[range.clone()].copy_from_slice(&decoded.payload[range]);
            prop_assert_eq!(
                start(&decoded.block, &garbled, index),
                Some(ordered[index]),
                "bytes outside the value's bit range are never consulted"
            );
        }

        #[test]
        fn any_flipped_payload_bit_is_caught(
            values in vec(any::<u64>(), 1..=BLOCK), pick in any::<usize>(), bit in 0_u32..8
        ) {
            let decoded = decode_starts(&sorted(values));
            let mut bytes = decoded.payload;
            if let Some(at) = pick.checked_rem(bytes.len()) {
                bytes[at] ^= 1_u8.rotate_left(bit);
                prop_assert!(!verify(&decoded.block, &bytes), "a flipped payload bit is caught");
            }
        }

        #[test]
        fn any_flipped_entry_bit_is_caught(
            values in vec(any::<u64>(), 1..=BLOCK), wide in 0_u32..64, bit in 0_u32..8
        ) {
            let decoded = decode_starts(&sorted(values));
            let block = decoded.block;
            let flipped = [
                Block { base: block.base ^ 1_u64.rotate_left(wide), ..block },
                Block { checksum: block.checksum ^ 1_u64.rotate_left(wide), ..block },
                Block { flags: block.flags ^ 1_u8.rotate_left(bit), ..block },
                Block { width: block.width ^ 1_u8.rotate_left(bit), ..block },
            ];
            for entry in flipped {
                prop_assert!(!verify(&entry, &decoded.payload), "a flipped entry bit is caught");
            }
        }
    }
}
