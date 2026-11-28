//! The JSON Lines sink of the export driver.

use arrow_array::RecordBatch;
use arrow_schema::{ArrowError, SchemaRef};
use serde_json::Value;

use crate::encode::{Binary, cell_value, check_encodable, encode_failure, write_stream};
use crate::error::MboxTurboError;
use crate::export::Exporter;
use crate::staging::{DestinationKind, Staged};

/// What error messages call this sink.
const SINK: &str = "JSONL";

/// Writes one JSON object per selected message, one per line, to a file or stream.
///
/// Each object is keyed by column name in selection column order. Text columns are strings,
/// integer columns numbers, boolean columns `true` or `false`, list columns arrays of the same,
/// struct columns objects keyed by field name, [`Column::Raw`](crate::Column::Raw) a standard
/// base64 string, and the date column an RFC 3339 UTC string with fractional seconds only when
/// non-zero. A missing value is `null`.
///
/// [`Exporter::begin`] refuses a schema holding a column type the sink cannot encode with an
/// [`MboxTurboError::UnsupportedColumn`] naming the column and the sink.
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
        check_encodable(schema, SINK, Binary::Allowed)
    }

    fn finish(&mut self, _staged: &mut Staged) -> Result<u64, MboxTurboError> {
        Ok(0)
    }

    fn write(&mut self, batch: &RecordBatch, staged: &mut Staged) -> Result<u64, MboxTurboError> {
        let encoded = encode_batch(batch).map_err(|source| encode_failure(SINK, staged, source))?;
        write_stream(staged, &encoded)
    }
}

/// The JSON lines of every row of `batch`.
fn encode_batch(batch: &RecordBatch) -> Result<Vec<u8>, ArrowError> {
    let mut encoded = Vec::new();
    for row in 0..batch.num_rows() {
        encode_row(&mut encoded, batch, row)?;
    }
    Ok(encoded)
}

/// Appends row `row` of `batch` to `buffer` as one JSON object and a newline.
fn encode_row(buffer: &mut Vec<u8>, batch: &RecordBatch, row: usize) -> Result<(), ArrowError> {
    buffer.push(b'{');
    for (index, field) in batch.schema().fields().iter().enumerate() {
        if index > 0 {
            buffer.push(b',');
        }
        let value = cell_value(batch.column(index).as_ref(), row)?;
        write_json(buffer, &Value::from(field.name().as_str()))?;
        buffer.push(b':');
        write_json(buffer, &value)?;
    }
    buffer.extend_from_slice(b"}\n");
    Ok(())
}

/// Appends `value` to `buffer` as JSON.
fn write_json(buffer: &mut Vec<u8>, value: &Value) -> Result<(), ArrowError> {
    serde_json::to_writer(buffer, value).map_err(|error| ArrowError::JsonError(error.to_string()))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;

    use arrow_array::builder::{
        ArrayBuilder, BooleanBuilder, ListBuilder, StringBuilder, StructBuilder, UInt32Builder,
    };
    use arrow_array::{ArrayRef, RecordBatch};
    use arrow_schema::{DataType, Field, Fields, Schema};

    use super::encode_batch;
    use crate::encode::{Binary, is_encodable};

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
            is_encodable(column.data_type(), Binary::Allowed),
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
}
