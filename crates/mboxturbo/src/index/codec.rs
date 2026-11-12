//! Block frame-of-reference codec: a block stores each value as its distance from the block's
//! minimum, packed into the fewest bits that hold the largest distance, so one value is read
//! from at most nine payload bytes and a checksummed directory entry guards the block.

use std::iter::repeat_n;

use xxhash_rust::xxh3::xxh3_64;

/// Flag bit of a dates block: its all-ones code means "no date" (stored as zero by callers).
pub(crate) const MISSING: u8 = 1;
/// Widest code a block can hold, in bits.
const MAX_WIDTH: u8 = 64;
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

/// Base, width and flags of a block before its payload is packed.
#[derive(Debug, Clone, Copy)]
struct Layout {
    /// Block minimum, as `u64` bits.
    base: u64,
    /// Flag bits for the entry.
    flags: u8,
    /// Bits per stored code.
    width: u8,
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

/// Reads the `width`-bit code at bit offset `bit` through a zero-padded 16-byte window, touching
/// at most nine payload bytes. `None` when `width` exceeds 64 or the bits are not all in `payload`.
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
    let mut window = [0_u8; 16];
    for (dst, src) in window
        .iter_mut()
        .zip(payload.get(byte..)?.iter().take(WINDOW))
    {
        *dst = *src;
    }
    let [b0, b1, b2, b3, b4, b5, b6, b7, ..] = u128::from_le_bytes(window)
        .checked_shr(shift)?
        .to_le_bytes();
    Some(u64::from_le_bytes([b0, b1, b2, b3, b4, b5, b6, b7]) & mask(width))
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
fn seal(
    layout: Layout,
    count: usize,
    codes: impl Iterator<Item = u64>,
    out: &mut Vec<u8>,
) -> Block {
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
        Layout {
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

/// Minimum and maximum of the non-zero dates, or `None` when there are none.
fn nonzero_span(values: &[i64]) -> Option<(i64, i64)> {
    let mut present = values.iter().copied().filter(|value| *value != 0);
    let first = present.next()?;
    Some(present.fold((first, first), |(low, high), value| {
        (low.min(value), high.max(value))
    }))
}

/// Chooses base, width and flags for a dates block: the "no date" sentinel is used only when zero
/// is outside the span of the present dates and the span leaves room for the all-ones code.
fn date_layout(values: &[i64]) -> Layout {
    let min = values.iter().copied().min().unwrap_or(0);
    let max = values.iter().copied().max().unwrap_or(0);
    let plain = Layout {
        base: bits_of(min),
        flags: 0,
        width: bit_width(max.abs_diff(min)),
    };
    let has_zero = values.contains(&0);
    let Some((low, high)) = nonzero_span(values).filter(|_| has_zero) else {
        return plain;
    };
    let width = bit_width(high.abs_diff(low));
    if (low <= 0 && high >= 0) || width >= MAX_WIDTH {
        return plain;
    }
    Layout {
        base: bits_of(low),
        flags: MISSING,
        width: width.saturating_add(1),
    }
}

/// Appends the payload of `values` (zero meaning "no date") to `out` and returns the entry.
pub(crate) fn encode_dates(values: &[i64], out: &mut Vec<u8>) -> Block {
    let layout = date_layout(values);
    let origin = signed_of(layout.base);
    let sentinel = mask(layout.width);
    let codes = values.iter().map(|value| {
        if layout.flags & MISSING != 0 && *value == 0 {
            sentinel
        } else {
            value.abs_diff(origin)
        }
    });
    seal(layout, values.len(), codes, out)
}

/// Whether `payload` and the entry's fields match the entry's checksum.
pub(crate) fn verify(block: &Block, payload: &[u8]) -> bool {
    checksum(block.base, block.width, block.flags, payload) == block.checksum
}

/// Code at `index`, or `None` when the entry or the payload cannot hold it.
fn code(block: &Block, payload: &[u8], index: usize) -> Option<u64> {
    let bit = index.checked_mul(usize::from(block.width))?;
    read_code(payload, bit, block.width)
}

/// Start at `index` of a starts block, or `None` for an unknown flag, a width above 64, or an
/// index the payload does not cover. An all-equal block (width 0) answers any index with its base.
pub(crate) fn start(block: &Block, payload: &[u8], index: usize) -> Option<u64> {
    if block.flags != 0 {
        return None;
    }
    block.base.checked_add(code(block, payload, index)?)
}

/// Date at `index` of a dates block, zero for "no date", or `None` for an unknown flag, a width
/// above 64, a sentinel block of width 0, or an index the payload does not cover.
pub(crate) fn date(block: &Block, payload: &[u8], index: usize) -> Option<i64> {
    if block.flags & !MISSING != 0 || (block.flags == MISSING && block.width == 0) {
        return None;
    }
    let raw = code(block, payload, index)?;
    if block.flags == MISSING && raw == mask(block.width) {
        return Some(0);
    }
    signed_of(block.base).checked_add_unsigned(raw)
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

    fn decode_dates(values: &[i64]) -> Decoded<i64> {
        let mut payload = Vec::new();
        let block = encode_dates(values, &mut payload);
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
        let dates = decode_dates(&[0_i64; 5]);
        assert_eq!(
            (dates.block.width, dates.payload.len()),
            (0, 0),
            "all-zero dates are equal values"
        );
        assert_eq!(dates.values, some(&[0_i64; 5]), "all-zero dates read back");
    }

    #[test]
    fn zero_outside_the_dates_uses_the_sentinel_and_keeps_the_width_small() {
        let values = [0, 1_700_000_000, 0, 1_700_000_300, 0];
        let decoded = decode_dates(&values);
        assert_eq!(
            decoded.block.flags, MISSING,
            "zero is below the present dates"
        );
        assert_eq!(
            decoded.block.width, 10,
            "a span of 300 is nine bits plus the sentinel"
        );
        assert_eq!(decoded.values, some(&values), "zeros come back as zeros");
    }

    #[test]
    fn zero_inside_the_dates_is_an_ordinary_value() {
        let values = [-5, 0, 7];
        let decoded = decode_dates(&values);
        assert_eq!(decoded.block.flags, 0, "zero lies within the span");
        assert_eq!(decoded.values, some(&values), "dates come back");
    }

    #[test]
    fn extremes_roundtrip() {
        let starts = decode_starts(&[0, u64::MAX]);
        assert_eq!(
            starts.values,
            some(&[0, u64::MAX]),
            "a 64-bit span survives"
        );
        let values = [i64::MIN, 0, i64::MAX];
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
                prop_oneof![Just(0_i64), any::<i64>(), 1_i64..100_000, -500_i64..500],
                0..=BLOCK,
            )
        ) {
            let decoded = decode_dates(&values);
            prop_assert_eq!(decoded.values, some(&values), "decoding returns the encoded dates");
            prop_assert!(verify(&decoded.block, &decoded.payload), "a fresh block verifies");
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
