//! The JSON Lines sink of the export driver.

use arrow_array::cast::AsArray as _;
use arrow_array::types::{
    Int8Type, Int32Type, Int64Type, TimestampMicrosecondType, UInt8Type, UInt32Type, UInt64Type,
};
use arrow_array::{Array, RecordBatch};
use arrow_schema::{ArrowError, DataType, SchemaRef, TimeUnit};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use mail_parser::DateTime;
use serde_json::{Map, Value};

use crate::error::MboxTurboError;
use crate::export::Exporter;
use crate::staging::{DestinationKind, Output, Staged};
use crate::width::widen;

/// Microseconds in a second.
const MICROS_PER_SECOND: i64 = 1_000_000;

/// Writes one JSON object per selected message, one per line, to a file or stream.
///
/// Each object is keyed by column name in selection column order. Text columns are strings,
/// integer columns numbers, boolean columns `true` or `false`, list columns arrays of the same,
/// struct columns objects keyed by field name, [`Column::Raw`](crate::Column::Raw) a standard
/// base64 string, and the date column an RFC 3339 UTC string with fractional seconds only when
/// non-zero. A missing value is `null`.
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

/// The JSON value of `array` at `row`: `null` for a missing value, an array for a list, an
/// object keyed by field name for a struct.
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
        DataType::Struct(_) => struct_value(array, row),
        _ => scalar_value(array, row),
    }
}

/// The JSON value of the non-nested `array` at `row`, which is not null.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Arrow has dozens of types and only the ones the columns produce are encoded"
)]
fn scalar_value(array: &dyn Array, row: usize) -> Result<Value, MboxTurboError> {
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
        other => Err(MboxTurboError::Arrow {
            positions: row..row.saturating_add(1),
            source: ArrowError::SchemaError(format!("the {other} type cannot be encoded")),
        }),
    }
}

/// The JSON object of the struct at `row`, keyed by field name.
fn struct_value(array: &dyn Array, row: usize) -> Result<Value, MboxTurboError> {
    let fields = array.as_struct();
    let mut object = Map::new();
    for (name, column) in fields.column_names().into_iter().zip(fields.columns()) {
        let value = cell_value(column.as_ref(), row)?;
        drop(object.insert(name.to_owned(), value));
    }
    Ok(Value::Object(object))
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

/// Whether `data_type` is one of the types the columns produce, or a list or struct of them.
#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Arrow has dozens of types and only the ones the columns produce are encoded"
)]
fn is_encodable(data_type: &DataType) -> bool {
    match data_type {
        DataType::List(field) => is_encodable(field.data_type()),
        DataType::Struct(fields) => fields.iter().all(|field| is_encodable(field.data_type())),
        DataType::Timestamp(unit, _) => *unit == TimeUnit::Microsecond,
        DataType::Utf8
        | DataType::Boolean
        | DataType::UInt8
        | DataType::UInt32
        | DataType::UInt64
        | DataType::Int8
        | DataType::Int32
        | DataType::Int64
        | DataType::LargeBinary => true,
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
pub(crate) mod tests {
    use std::sync::Arc;

    use arrow_array::builder::{
        ArrayBuilder, BooleanBuilder, ListBuilder, StringBuilder, StructBuilder, UInt32Builder,
    };
    use arrow_array::{ArrayRef, RecordBatch};
    use arrow_schema::{DataType, Field, Fields, Schema};

    use super::{encode_batch, is_encodable, rfc3339_micros};

    /// One struct of the `sets` column.
    struct Set {
        count: Option<u32>,
        flag: bool,
        name: &'static str,
        tags: &'static [&'static str],
    }

    /// Appends `set` to `item`.
    fn append_set(item: &mut StructBuilder, set: &Set) {
        let Set {
            count,
            flag,
            name,
            tags,
        } = *set;
        item.field_builder::<StringBuilder>(0)
            .expect("field 0 is a string builder")
            .append_value(name);
        item.field_builder::<UInt32Builder>(1)
            .expect("field 1 is an integer builder")
            .append_option(count);
        item.field_builder::<BooleanBuilder>(2)
            .expect("field 2 is a boolean builder")
            .append_value(flag);
        let list = item
            .field_builder::<ListBuilder<StringBuilder>>(3)
            .expect("field 3 is a list builder");
        for tag in tags {
            list.values().append_value(tag);
        }
        list.append(true);
        item.append(true);
    }

    /// An empty builder of the `sets` structs.
    fn set_builder() -> StructBuilder {
        let tags_type = DataType::List(Arc::new(Field::new("item", DataType::Utf8, true)));
        let fields = Fields::from(vec![
            Field::new("name", DataType::Utf8, false),
            Field::new("count", DataType::UInt32, true),
            Field::new("flag", DataType::Boolean, false),
            Field::new("tags", tags_type, true),
        ]);
        let builders: Vec<Box<dyn ArrayBuilder>> = vec![
            Box::new(StringBuilder::new()),
            Box::new(UInt32Builder::new()),
            Box::new(BooleanBuilder::new()),
            Box::new(ListBuilder::new(StringBuilder::new())),
        ];
        StructBuilder::new(fields, builders)
    }

    /// A `List<Struct>` array of one row holding two structs, the second with a null `count`
    /// and an empty nested `tags` list.
    pub(crate) fn sets_column() -> ArrayRef {
        let mut sets = ListBuilder::new(set_builder());
        append_set(
            sets.values(),
            &Set {
                name: "spf",
                count: Some(1),
                flag: true,
                tags: &["a", "b"],
            },
        );
        append_set(
            sets.values(),
            &Set {
                name: "dkim",
                count: None,
                flag: false,
                tags: &[],
            },
        );
        sets.append(true);
        Arc::new(sets.finish())
    }

    #[test]
    fn a_list_of_structs_is_an_array_of_objects_with_null_fields_and_nested_lists() {
        let column = sets_column();
        let schema = Schema::new(vec![Field::new("sets", column.data_type().clone(), true)]);
        assert!(
            is_encodable(column.data_type()),
            "a list of structs of encodable fields is accepted"
        );
        let batch = RecordBatch::try_new(Arc::new(schema), vec![column])
            .expect("the batch matches its schema");
        let encoded = encode_batch(&batch).expect("the batch encodes");
        assert_eq!(
            String::from_utf8(encoded).expect("the line is UTF-8"),
            concat!(
                r#"{"sets":[{"count":1,"flag":true,"name":"spf","tags":["a","b"]},"#,
                r#"{"count":null,"flag":false,"name":"dkim","tags":[]}]}"#,
                "\n"
            ),
            "each struct is an object keyed by field name"
        );
    }

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
