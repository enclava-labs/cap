//! Minimal FieldsV1 interpretation for classifying server-side apply
//! ownership conflicts.
//!
//! This is deliberately not a general SSA simulator. It flattens one
//! managed-fields entry into the dotted field-path notation the API server
//! uses in `Status.details.causes[].field`, and refuses (`None`) on any shape
//! it cannot attribute so callers can fail closed.

use serde_json::Value;

/// Flatten a managed-fields `fieldsV1` document into the dotted paths it
/// owns, in `StatusCause::field` notation with the leading dot stripped.
///
/// `f:name` names a field; `k:{"name":"x"}` names an associative-list element
/// (rendered `[name=x]`). An empty object marks a leaf owning that path and
/// everything below it. `None` means the document claims fields this walker
/// cannot attribute; callers must treat that as owning everything.
pub(super) fn flatten_owned_paths(fields_v1: &Value) -> Option<Vec<String>> {
    let mut paths = Vec::new();
    flatten_into(fields_v1, String::new(), &mut paths)?;
    Some(paths)
}

fn flatten_into(node: &Value, prefix: String, paths: &mut Vec<String>) -> Option<()> {
    let object = node.as_object()?;
    for (key, child) in object {
        let segment = segment(key)?;
        let path = if prefix.is_empty() || segment.starts_with('[') {
            format!("{prefix}{segment}")
        } else {
            format!("{prefix}.{segment}")
        };
        if child
            .as_object()
            .is_some_and(|children| children.is_empty())
        {
            paths.push(path);
        } else {
            flatten_into(child, path, paths)?;
        }
    }
    Some(())
}

fn segment(key: &str) -> Option<String> {
    if let Some(field) = key.strip_prefix("f:") {
        return (!field.is_empty()).then(|| field.to_string());
    }
    if let Some(list_key) = key.strip_prefix("k:") {
        let value: std::collections::BTreeMap<String, Value> =
            serde_json::from_str(list_key).ok()?;
        if value.len() != 1 {
            return None;
        }
        let (name, marker) = value.into_iter().next()?;
        Some(format!("[{}={}]", name, marker.as_str()?))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn flattens_fields_annotations_and_associative_lists() {
        let fields = json!({
            "f:metadata": {
                "f:annotations": {
                    "f:enclava.dev/cap-provider-mutation-generation": {}
                }
            },
            "f:spec": {
                "f:replicas": {},
                "f:containers": {
                    "k:{\"name\":\"workload\"}": {
                        "f:image": {}
                    }
                }
            }
        });
        let mut paths = flatten_owned_paths(&fields).expect("attributable");
        paths.sort();
        assert_eq!(
            paths,
            vec![
                "metadata.annotations.enclava.dev/cap-provider-mutation-generation",
                "spec.containers[name=workload].image",
                "spec.replicas",
            ]
        );
    }

    #[test]
    fn empty_subtree_leaf_owns_whole_subtree() {
        let fields = json!({"f:spec": {}});
        assert_eq!(flatten_owned_paths(&fields), Some(vec!["spec".to_string()]));
    }

    #[test]
    fn unattributable_shapes_fail_closed() {
        assert_eq!(flatten_owned_paths(&json!({"v:8080": {}})), None);
        assert_eq!(flatten_owned_paths(&json!({"f:spec": "scalar"})), None);
        assert_eq!(
            flatten_owned_paths(&json!({"k:{\"name\":\"a\",\"x\":\"b\"}": {}})),
            None
        );
        assert_eq!(flatten_owned_paths(&json!("not-an-object")), None);
    }
}
