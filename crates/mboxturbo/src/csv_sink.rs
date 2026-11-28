//! The CSV sink of the export driver.

use arrow_array::{Array, RecordBatch};
use arrow_schema::{ArrowError, SchemaRef};
use serde_json::Value;

use crate::encode::{Binary, cell_value, check_encodable, encode_failure, write_stream};
use crate::error::MboxTurboError;
use crate::export::Exporter;
use crate::staging::{DestinationKind, Staged};

/// What error messages call this sink.
const SINK: &str = "CSV";

/// Whether the CSV sink defuses cells a spreadsheet would read as a formula.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum FormulaEscaping {
    /// Text cells are written as selected.
    Off,
    /// Text cells starting with `=`, `+`, `-`, `@`, a tab or a carriage return get a leading
    /// apostrophe. Numeric cells are never altered.
    #[default]
    Prefix,
}

/// Writes a header row and one RFC 4180 row per selected message, to a file or stream.
///
/// The header holds the selected column names in selection order and every row ends in CRLF. A
/// field holding a comma, double quote, CR or LF is quoted with its double quotes doubled. List
/// and struct columns are one compact JSON-encoded cell as in the JSONL sink, the date column an
/// RFC 3339 UTC string, and a missing value an empty cell.
///
/// [`Exporter::begin`] refuses a schema holding a column type the sink cannot encode, such as
/// [`Column::Raw`](crate::Column::Raw), with an [`MboxTurboError::UnsupportedColumn`] naming the
/// column and the sink, before anything is written.
#[derive(Debug, Clone, Copy)]
pub struct CsvExporter {
    /// How text cells that look like formulas are written.
    escaping: FormulaEscaping,
}

impl CsvExporter {
    /// A sink that writes each selected message as a CSV row, escaping formulas per `escaping`.
    #[must_use]
    pub const fn new(escaping: FormulaEscaping) -> Self {
        Self { escaping }
    }
}

impl Exporter for CsvExporter {
    fn accepts(&self, kind: DestinationKind) -> bool {
        kind != DestinationKind::Directory
    }

    fn begin(&mut self, schema: &SchemaRef, staged: &mut Staged) -> Result<(), MboxTurboError> {
        check_encodable(schema, SINK, Binary::Refused)?;
        let mut header = Vec::new();
        for (index, field) in schema.fields().iter().enumerate() {
            push_field(&mut header, index, field.name());
        }
        header.extend_from_slice(b"\r\n");
        write_stream(staged, &header).map(drop)
    }

    fn finish(&mut self, _staged: &mut Staged) -> Result<u64, MboxTurboError> {
        Ok(0)
    }

    fn write(&mut self, batch: &RecordBatch, staged: &mut Staged) -> Result<u64, MboxTurboError> {
        let mut encoded = Vec::new();
        for row in 0..batch.num_rows() {
            for (index, column) in batch.columns().iter().enumerate() {
                let cell = cell_text(column.as_ref(), row, self.escaping)
                    .map_err(|source| encode_failure(SINK, staged, source))?;
                push_field(&mut encoded, index, &cell);
            }
            encoded.extend_from_slice(b"\r\n");
        }
        write_stream(staged, &encoded)
    }
}

/// The text of the cell of `array` at `row`.
fn cell_text(
    array: &dyn Array,
    row: usize,
    escaping: FormulaEscaping,
) -> Result<String, ArrowError> {
    let value = cell_value(array, row)?;
    Ok(match value {
        Value::Null => String::new(),
        Value::String(text) => escape_formula(text, escaping),
        Value::Bool(_) | Value::Number(_) | Value::Array(_) | Value::Object(_) => value.to_string(),
    })
}

/// `text` with a leading apostrophe when it starts like a spreadsheet formula.
fn escape_formula(text: String, escaping: FormulaEscaping) -> String {
    let risky = matches!(
        text.as_bytes().first(),
        Some(b'=' | b'+' | b'-' | b'@' | b'\t' | b'\r')
    );
    if escaping == FormulaEscaping::Prefix && risky {
        format!("'{text}")
    } else {
        text
    }
}

/// Appends `text` to `buffer` as the field at column `index`, comma-separated and quoted when
/// it holds a comma, double quote, CR or LF.
fn push_field(buffer: &mut Vec<u8>, index: usize, text: &str) {
    if index > 0 {
        buffer.push(b',');
    }
    if text.contains([',', '"', '\r', '\n']) {
        buffer.push(b'"');
        buffer.extend_from_slice(text.replace('"', "\"\"").as_bytes());
        buffer.push(b'"');
    } else {
        buffer.extend_from_slice(text.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::{FormulaEscaping, cell_text};
    use crate::encode::fixtures::sets_column;
    use crate::encode::{Binary, is_encodable};

    #[test]
    fn a_list_of_structs_is_one_compact_json_cell() {
        let column = sets_column();
        assert!(
            is_encodable(column.data_type(), Binary::Refused),
            "a list of structs of encodable fields is accepted"
        );
        assert_eq!(
            cell_text(column.as_ref(), 0, FormulaEscaping::Prefix).expect("the cell encodes"),
            concat!(
                r#"[{"count":1,"flag":true,"name":"spf","tags":["a","b"]},"#,
                r#"{"count":null,"flag":false,"name":"dkim","tags":[]}]"#
            ),
            "the cell is the JSONL value as compact text"
        );
    }
}
