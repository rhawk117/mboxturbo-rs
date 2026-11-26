//! The JSON Lines sink of the export driver.

use arrow_array::cast::AsArray as _;
use arrow_array::types::{Int32Type, TimestampMicrosecondType, UInt64Type};
use arrow_array::{Array, RecordBatch};
use arrow_schema::{ArrowError, DataType, SchemaRef, TimeUnit};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use mail_parser::DateTime;
use serde_json::Value;

use crate::error::MboxTurboError;
use crate::export::Exporter;
use crate::staging::{DestinationKind, Output, Staged};
use crate::width::widen;

/// Microseconds in a second.
const MICROS_PER_SECOND: i64 = 1_000_000;

/// Writes one JSON object per selected message, one per line, to a file or stream.
///
/// Each object is keyed by column name in selection column order. Text columns are strings,
/// integer columns numbers, list columns arrays of the same, [`Column::Raw`](crate::Column::Raw)
/// a standard base64 string, and the date column an RFC 3339 UTC string with fractional seconds
/// only when non-zero. A missing value is `null`.
///
/// [`Exporter::begin`] refuses a schema holding a column type the sink cannot encode with an
/// [`MboxTurboError::Arrow`] schema error naming the column.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct JsonlExporter;

impl JsonlExporter {
    /// A sink that writes each selected message as a JSON line.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Exporter for JsonlExporter {
    fn accepts(&self, kind: DestinationKind) -> bool {
        kind != DestinationKind::Directory
    }

    fn begin(&mut self, schema: &SchemaRef, _staged: &mut Staged) -> Result<(), MboxTurboError> {
        for field in schema.fields() {
            if !is_encodable(field.data_type()) {
                return Err(MboxTurboError::Arrow {
                    positions: 0..0,
                    source: ArrowError::SchemaError(format!(
                        "the `{}` column has a type the JSONL sink cannot encode: {}",
                        field.name(),
                        field.data_type()
                    )),
                });
            }
        }
        Ok(())
    }

    fn finish(&mut self, _staged: &mut Staged) -> Result<u64, MboxTurboError> {
        Ok(0)
    }

    fn write(&mut self, batch: &RecordBatch, staged: &mut Staged) -> Result<u64, MboxTurboError> {
        let encoded = encode_batch(batch)?;
        let Output::Writer(destination) = staged.output() else {
            // `accepts` refuses directory destinations
            return Err(staged.unsupported());
        };
        let written = destination.write_all(&encoded);
        written.map_err(|source| MboxTurboError::io(staged.target_label(), source))?;
        Ok(widen(encoded.len()))
    }
}

/// The JSON value of `array` at `row`: `null` for a missing value, an array for a list.
///
/// # Errors
///
/// An [`MboxTurboError::Arrow`] schema error for an array type the columns never produce.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Arrow has dozens of types and only the ones the columns produce are encoded"
)]
pub(crate) fn cell_value(array: &dyn Array, row: usize) -> Result<Value, MboxTurboError> {
    if array.is_null(row) {
        return Ok(Value::Null);
    }
    match array.data_type() {
        DataType::List(_) => list_value(array, row),
        DataType::Utf8 => Ok(Value::from(array.as_string::<i32>().value(row))),
        DataType::UInt64 => Ok(Value::from(array.as_primitive::<UInt64Type>().value(row))),
        DataType::Int32 => Ok(Value::from(array.as_primitive::<Int32Type>().value(row))),
        DataType::Timestamp(TimeUnit::Microsecond, _) => Ok(Value::from(rfc3339_micros(
            array.as_primitive::<TimestampMicrosecondType>().value(row),
        ))),
        DataType::LargeBinary => Ok(Value::from(
            STANDARD.encode(array.as_binary::<i64>().value(row)),
        )),
        other => Err(MboxTurboError::Arrow {
            positions: row..row.saturating_add(1),
            source: ArrowError::SchemaError(format!("the {other} type cannot be encoded")),
        }),
    }
}

/// `micros` since the epoch as an RFC 3339 UTC string, with fractional seconds only when
/// non-zero.
pub(crate) fn rfc3339_micros(micros: i64) -> String {
    let date = DateTime::from_timestamp(micros.div_euclid(MICROS_PER_SECOND));
    let mut text = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        date.year, date.month, date.day, date.hour, date.minute, date.second
    );
    let fraction = micros.rem_euclid(MICROS_PER_SECOND);
    if fraction != 0 {
        let digits = format!("{fraction:06}");
        text.push('.');
        text.push_str(digits.trim_end_matches('0'));
    }
    text.push('Z');
    text
}

/// The JSON lines of every row of `batch`.
fn encode_batch(batch: &RecordBatch) -> Result<Vec<u8>, MboxTurboError> {
    let mut encoded = Vec::new();
    for row in 0..batch.num_rows() {
        encode_row(&mut encoded, batch, row)?;
    }
    Ok(encoded)
}

/// Appends row `row` of `batch` to `buffer` as one JSON object and a newline.
fn encode_row(buffer: &mut Vec<u8>, batch: &RecordBatch, row: usize) -> Result<(), MboxTurboError> {
    buffer.push(b'{');
    for (index, field) in batch.schema().fields().iter().enumerate() {
        if index > 0 {
            buffer.push(b',');
        }
        let value = cell_value(batch.column(index).as_ref(), row)?;
        write_json(buffer, &Value::from(field.name().as_str()), row)?;
        buffer.push(b':');
        write_json(buffer, &value, row)?;
    }
    buffer.extend_from_slice(b"}\n");
    Ok(())
}

/// Whether `data_type` is one of the types the columns produce, or a list of one.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Arrow has dozens of types and only the ones the columns produce are encoded"
)]
fn is_encodable(data_type: &DataType) -> bool {
    match data_type {
        DataType::List(field) => is_encodable(field.data_type()),
        DataType::Timestamp(unit, _) => *unit == TimeUnit::Microsecond,
        DataType::Utf8 | DataType::UInt64 | DataType::Int32 | DataType::LargeBinary => true,
        _ => false,
    }
}

/// The JSON array of the list at `row`.
fn list_value(array: &dyn Array, row: usize) -> Result<Value, MboxTurboError> {
    let items = array.as_list::<i32>().value(row);
    let values = (0..items.len())
        .map(|item| cell_value(items.as_ref(), item))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Value::Array(values))
}

/// Appends `value` to `buffer` as JSON.
fn write_json(buffer: &mut Vec<u8>, value: &Value, row: usize) -> Result<(), MboxTurboError> {
    serde_json::to_writer(buffer, value).map_err(|error| MboxTurboError::Arrow {
        positions: row..row.saturating_add(1),
        source: ArrowError::JsonError(error.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::rfc3339_micros;

    #[test]
    fn fractional_seconds_appear_only_when_non_zero_without_trailing_zeros() {
        assert_eq!(
            rfc3339_micros(1_704_096_000_000_000),
            "2024-01-01T08:00:00Z",
            "whole seconds carry no fraction"
        );
        assert_eq!(
            rfc3339_micros(1_704_096_000_500_000),
            "2024-01-01T08:00:00.5Z",
            "trailing zeros of the fraction are trimmed"
        );
        assert_eq!(
            rfc3339_micros(1_704_096_000_000_001),
            "2024-01-01T08:00:00.000001Z",
            "leading zeros of the fraction are kept"
        );
        assert_eq!(
            rfc3339_micros(-500_000),
            "1969-12-31T23:59:59.5Z",
            "a time before the epoch rounds down to the second"
        );
    }
}
