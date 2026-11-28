//! What the export sinks share: encoding a cell, checking a schema, finding a column and writing
//! to the staged stream.

use arrow_array::Array;
use arrow_array::cast::AsArray as _;
use arrow_array::types::{
    Int8Type, Int32Type, Int64Type, TimestampMicrosecondType, UInt8Type, UInt32Type, UInt64Type,
};
use arrow_schema::{ArrowError, DataType, SchemaRef, TimeUnit};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use mail_parser::DateTime;
use serde_json::{Map, Value};

use crate::columns::Column;
use crate::error::MboxTurboError;
use crate::staging::{Output, Staged};
use crate::width::widen;

/// Microseconds in a second.
const MICROS_PER_SECOND: i64 = 1_000_000;

/// Whether a sink writes binary columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Binary {
    /// Binary columns are encoded, as base64 text.
    Allowed,
    /// A binary column is refused.
    Refused,
}

/// The JSON value of `array` at `row`: `null` for a missing value, an array for a list, an
/// object keyed by field name for a struct.
///
/// # Errors
///
/// An [`ArrowError::SchemaError`] for an array type the columns never produce.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Arrow has dozens of types and only the ones the columns produce are encoded"
)]
pub(crate) fn cell_value(array: &dyn Array, row: usize) -> Result<Value, ArrowError> {
    if array.is_null(row) {
        return Ok(Value::Null);
    }
    match array.data_type() {
        DataType::List(_) => list_value(array, row),
        DataType::Struct(_) => struct_value(array, row),
        _ => scalar_value(array, row),
    }
}

/// The JSON value of the non-nested `array` at `row`, which is not null.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Arrow has dozens of types and only the ones the columns produce are encoded"
)]
fn scalar_value(array: &dyn Array, row: usize) -> Result<Value, ArrowError> {
    match array.data_type() {
        DataType::Utf8 => Ok(Value::from(array.as_string::<i32>().value(row))),
        DataType::Boolean => Ok(Value::from(array.as_boolean().value(row))),
        DataType::UInt8 => Ok(Value::from(array.as_primitive::<UInt8Type>().value(row))),
        DataType::UInt32 => Ok(Value::from(array.as_primitive::<UInt32Type>().value(row))),
        DataType::UInt64 => Ok(Value::from(array.as_primitive::<UInt64Type>().value(row))),
        DataType::Int8 => Ok(Value::from(array.as_primitive::<Int8Type>().value(row))),
        DataType::Int32 => Ok(Value::from(array.as_primitive::<Int32Type>().value(row))),
        DataType::Int64 => Ok(Value::from(array.as_primitive::<Int64Type>().value(row))),
        DataType::Timestamp(TimeUnit::Microsecond, _) => Ok(Value::from(rfc3339_micros(
            array.as_primitive::<TimestampMicrosecondType>().value(row),
        ))),
        DataType::LargeBinary => Ok(Value::from(
            STANDARD.encode(array.as_binary::<i64>().value(row)),
        )),
        other => Err(ArrowError::SchemaError(format!(
            "the {other} type cannot be encoded"
        ))),
    }
}

/// The JSON object of the struct at `row`, keyed by field name.
fn struct_value(array: &dyn Array, row: usize) -> Result<Value, ArrowError> {
    let fields = array.as_struct();
    let mut object = Map::new();
    for (name, column) in fields.column_names().into_iter().zip(fields.columns()) {
        let value = cell_value(column.as_ref(), row)?;
        drop(object.insert(name.to_owned(), value));
    }
    Ok(Value::Object(object))
}

/// The JSON array of the list at `row`.
fn list_value(array: &dyn Array, row: usize) -> Result<Value, ArrowError> {
    let items = array.as_list::<i32>().value(row);
    let values = (0..items.len())
        .map(|item| cell_value(items.as_ref(), item))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Value::Array(values))
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

/// Whether `data_type` is one of the types the columns produce, or a list or struct of them;
/// binary only when `binary` allows it.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Arrow has dozens of types and only the ones the columns produce are encoded"
)]
pub(crate) fn is_encodable(data_type: &DataType, binary: Binary) -> bool {
    match data_type {
        DataType::List(field) => is_encodable(field.data_type(), binary),
        DataType::Struct(fields) => fields
            .iter()
            .all(|field| is_encodable(field.data_type(), binary)),
        DataType::Timestamp(unit, _) => *unit == TimeUnit::Microsecond,
        DataType::Utf8
        | DataType::Boolean
        | DataType::UInt8
        | DataType::UInt32
        | DataType::UInt64
        | DataType::Int8
        | DataType::Int32
        | DataType::Int64 => true,
        DataType::LargeBinary => binary == Binary::Allowed,
        _ => false,
    }
}

/// Refuses a schema holding a column `sink` cannot encode, naming the first such column.
///
/// # Errors
///
/// [`MboxTurboError::UnsupportedColumn`] for that column.
pub(crate) fn check_encodable(
    schema: &SchemaRef,
    sink: &'static str,
    binary: Binary,
) -> Result<(), MboxTurboError> {
    schema
        .fields()
        .iter()
        .find(|field| !is_encodable(field.data_type(), binary))
        .map_or(Ok(()), |field| {
            Err(MboxTurboError::UnsupportedColumn {
                column: field.name().clone(),
                sink,
                reason: "its type cannot be encoded by this sink",
            })
        })
}

/// The index of `column` in `schema`.
///
/// # Errors
///
/// [`MboxTurboError::UnsupportedColumn`] naming the column and `sink` when the export did not
/// extract it.
pub(crate) fn column_index(
    schema: &SchemaRef,
    column: &Column,
    sink: &'static str,
) -> Result<usize, MboxTurboError> {
    let name = column.name();
    schema
        .index_of(&name)
        .map_err(|_missing| MboxTurboError::UnsupportedColumn {
            column: name.into_owned(),
            sink,
            reason: "the export did not extract it",
        })
}

/// The error for a null `raw` or `position` value at `row` of a batch.
pub(crate) fn null_error(row: usize) -> MboxTurboError {
    MboxTurboError::Arrow {
        positions: row..row.saturating_add(1),
        source: ArrowError::SchemaError("the `raw` and `position` columns must not be null".into()),
    }
}

/// An encoder failure of `sink` writing to the destination `staged` stands for.
pub(crate) fn encode_failure(
    sink: &'static str,
    staged: &Staged,
    source: ArrowError,
) -> MboxTurboError {
    MboxTurboError::Encode {
        sink,
        target: staged.target_label().display().to_string(),
        source: Box::new(source),
    }
}

/// Writes `bytes` to the staged file or stream and returns how many.
///
/// # Errors
///
/// [`MboxTurboError::UnsupportedDestination`] for a directory, which the sinks that call this
/// refuse in `accepts`, and [`MboxTurboError::Io`] when the write fails.
pub(crate) fn write_stream(staged: &mut Staged, bytes: &[u8]) -> Result<u64, MboxTurboError> {
    let Output::Writer(destination) = staged.output() else {
        // `accepts` refuses directory destinations
        return Err(staged.unsupported());
    };
    let written = destination.write_all(bytes);
    written.map_err(|source| MboxTurboError::io(staged.target_label(), source))?;
    Ok(widen(bytes.len()))
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
