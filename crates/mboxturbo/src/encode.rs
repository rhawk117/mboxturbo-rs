//! What the export sinks share: encoding a cell, checking a schema, finding a column and writing
//! to the staged stream.

use std::path::Path;

use arrow_array::Array;
use arrow_array::cast::AsArray as _;
use arrow_array::types::{
    Int8Type, Int32Type, Int64Type, TimestampMicrosecondType, UInt8Type, UInt32Type, UInt64Type,
};
use arrow_schema::{ArrowError, DataType, SchemaRef, TimeUnit};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use mboxturbo_headers::rfc3339_micros;
use serde_json::{Map, Value};

use crate::columns::Column;
use crate::error::MboxTurboError;
use crate::staging::{Output, Staged};
use crate::width::widen;

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

/// The index of `column` in `schema`, or `None` when the export did not extract it.
pub(crate) fn optional_index(schema: &SchemaRef, column: &Column) -> Option<usize> {
    schema
        .column_with_name(&column.name())
        .map(|(index, _field)| index)
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
    optional_index(schema, column).ok_or_else(|| MboxTurboError::UnsupportedColumn {
        column: column.name().into_owned(),
        sink,
        reason: "the export did not extract it",
    })
}

/// An encoder failure of `sink` writing to the destination `staged` stands for.
pub(crate) fn encode_failure(
    sink: &'static str,
    staged: &Staged,
    source: ArrowError,
) -> MboxTurboError {
    MboxTurboError::Encode {
        sink,
        target: staged.target().map(Path::to_path_buf),
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
    written.map_err(|source| MboxTurboError::write_failure(staged.target(), source))?;
    Ok(widen(bytes.len()))
}

#[cfg(test)]
pub(crate) mod fixtures {
    use std::sync::Arc;

    use arrow_array::ArrayRef;
    use arrow_array::builder::{
        ArrayBuilder, BooleanBuilder, ListBuilder, StringBuilder, StructBuilder, UInt32Builder,
    };
    use arrow_schema::{DataType, Field, Fields};

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
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arrow_array::{Array as _, ArrayRef, Int8Array, StructArray, UInt8Array};
    use arrow_schema::{DataType, Field};
    use serde_json::json;

    use super::{Binary, cell_value, is_encodable};

    #[test]
    fn small_unsigned_and_signed_integers_encode_as_json_numbers() {
        let unsigned: ArrayRef = Arc::new(UInt8Array::from(vec![255_u8]));
        let signed: ArrayRef = Arc::new(Int8Array::from(vec![-128_i8]));
        let cells = StructArray::from(vec![
            (
                Arc::new(Field::new("unsigned", DataType::UInt8, false)),
                unsigned,
            ),
            (
                Arc::new(Field::new("signed", DataType::Int8, false)),
                signed,
            ),
        ]);
        assert!(
            is_encodable(cells.data_type(), Binary::Refused),
            "a struct of UInt8 and Int8 fields is accepted"
        );
        assert_eq!(
            cell_value(&cells, 0).expect("the small integers encode"),
            json!({"signed": -128_i64, "unsigned": 255_u64}),
            "each value keeps its sign and its extreme"
        );
    }
}
