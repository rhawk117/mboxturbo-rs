//! The hand-written validator that checks events against `schema/events-v1.json`, shared by the
//! integration tests that read the event stream.

#![expect(
    clippy::redundant_pub_crate,
    reason = "contradicts rustc's unreachable_pub, which is the lint this workspace keeps"
)]

use serde_json::Value;

const SCHEMA: &str = include_str!("../../schema/events-v1.json");

/// Keywords that only annotate: the validator accepts and ignores them.
const ANNOTATIONS: [&str; 3] = ["$schema", "title", "description"];

/// The parsed event schema.
pub(crate) fn schema() -> Value {
    serde_json::from_str(SCHEMA).expect("the schema is JSON")
}

/// The ways `value` breaks `schema`, none when it is valid. Supports exactly the keywords
/// `events-v1.json` uses; any other keyword panics so the schema cannot outgrow this check.
pub(crate) fn violations(schema: &Value, value: &Value) -> Vec<String> {
    let keywords = schema.as_object().expect("a schema is an object");
    let mut found = Vec::new();
    for (keyword, argument) in keywords {
        match keyword.as_str() {
            key if ANNOTATIONS.contains(&key) => {},
            "type" => found.extend(check_type(argument, value)),
            "required" => found.extend(check_required(argument, value)),
            "properties" => found.extend(check_properties(argument, value)),
            "additionalProperties" => {
                found.extend(check_additional(keywords, argument, value));
            },
            "const" => {
                found.extend((argument != value).then(|| format!("{value} is not {argument}")));
            },
            "enum" => found.extend(check_enum(argument, value)),
            "minimum" => found.extend(check_minimum(argument, value)),
            "oneOf" => found.extend(check_one_of(argument, value)),
            other => panic!("the validator does not know the keyword `{other}`"),
        }
    }
    found
}

fn check_type(expected: &Value, value: &Value) -> Vec<String> {
    let matches = match expected.as_str().expect("a type is a string") {
        "object" => value.is_object(),
        "string" => value.is_string(),
        "integer" => value.is_u64() || value.is_i64(),
        other => panic!("the validator does not know the type `{other}`"),
    };
    (!matches)
        .then(|| format!("{value} is not of type {expected}"))
        .into_iter()
        .collect()
}

fn check_minimum(minimum: &Value, value: &Value) -> Vec<String> {
    let limit = minimum.as_i64().expect("a minimum is an integer");
    let below = value.as_i64().is_some_and(|number| number < limit);
    (below)
        .then(|| format!("{value} is below the minimum {limit}"))
        .into_iter()
        .collect()
}

fn check_required(required: &Value, value: &Value) -> Vec<String> {
    let Some(object) = value.as_object() else {
        return Vec::new();
    };
    required
        .as_array()
        .expect("required is an array")
        .iter()
        .map(|member| member.as_str().expect("a required name is a string"))
        .filter(|member| !object.contains_key(*member))
        .map(|member| format!("`{member}` is missing"))
        .collect()
}

fn check_properties(properties: &Value, value: &Value) -> Vec<String> {
    let Some(object) = value.as_object() else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for (member, subschema) in properties.as_object().expect("properties is an object") {
        if let Some(content) = object.get(member) {
            found.extend(
                violations(subschema, content)
                    .into_iter()
                    .map(|reason| format!("`{member}`: {reason}")),
            );
        }
    }
    found
}

fn check_additional(
    keywords: &serde_json::Map<String, Value>,
    argument: &Value,
    value: &Value,
) -> Vec<String> {
    assert_eq!(
        argument,
        &Value::Bool(false),
        "the validator supports only additionalProperties: false"
    );
    let Some(object) = value.as_object() else {
        return Vec::new();
    };
    let known = keywords
        .get("properties")
        .and_then(Value::as_object)
        .expect("additionalProperties: false comes with properties");
    object
        .keys()
        .filter(|member| !known.contains_key(*member))
        .map(|member| format!("`{member}` is not allowed"))
        .collect()
}

fn check_enum(allowed: &Value, value: &Value) -> Vec<String> {
    let listed = allowed
        .as_array()
        .expect("enum is an array")
        .contains(value);
    (!listed)
        .then(|| format!("{value} is not one of {allowed}"))
        .into_iter()
        .collect()
}

fn check_one_of(subschemas: &Value, value: &Value) -> Vec<String> {
    let matching = subschemas
        .as_array()
        .expect("oneOf is an array")
        .iter()
        .filter(|subschema| violations(subschema, value).is_empty())
        .count();
    (matching != 1)
        .then(|| format!("{matching} subschemas match, not exactly one"))
        .into_iter()
        .collect()
}
