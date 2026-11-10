//! Serde helpers for wire fields that must distinguish omission from null.

use serde::{Deserialize, Deserializer};

/// Map a present JSON value to `Some`, including JSON null as `Some(None)`
/// when `T` is `Option<U>`.
///
/// Serde's `Option` deserializer treats a missing field and JSON null as the
/// same `None`, even for `Option<Option<U>>`. Pair this with
/// `#[serde(default)]` so a missing field stays `None` and an explicit null
/// becomes `Some(None)`.
pub fn deserialize_some<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[cfg(test)]
mod tests {
    use super::deserialize_some;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct Wire {
        #[serde(default, deserialize_with = "deserialize_some")]
        log_encryption: Option<Option<String>>,
    }

    #[test]
    fn missing_null_and_value_stay_distinct() {
        let absent: Wire = serde_json::from_str("{}").unwrap();
        assert_eq!(absent.log_encryption, None);

        let null: Wire = serde_json::from_str(r#"{"log_encryption":null}"#).unwrap();
        assert_eq!(null.log_encryption, Some(None));

        let value: Wire = serde_json::from_str(r#"{"log_encryption":"recipient"}"#).unwrap();
        assert_eq!(value.log_encryption, Some(Some("recipient".to_string())));
    }
}
