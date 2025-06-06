use serde_json::Value;

use crate::policy_error::policy_error::PolicyError;

pub struct ParameterFilter;

impl ParameterFilter {
    pub fn validate_query_params(query_params: &Value) -> Result<(), PolicyError> {
        if !query_params.is_object() {
            return Err(PolicyError::IncorrectFormatError("Query parameters must be an object".to_string()));
        }
        let obj = query_params.as_object().unwrap();
        if obj.len() > 0 {
            for key in obj.keys() {
                if key != "ids" && key != "attester_type" {
                    return Err(PolicyError::IncorrectFormatError(format!("Unsupported query parameter: {}", key)));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn test_validate_query_params_not_object() {
        let params = json!("not_object");
        let result = ParameterFilter::validate_query_params(&params);
        assert!(matches!(result, Err(PolicyError::IncorrectFormatError(msg)) if msg.contains("must be an object")));
    }

    #[test]
    fn test_validate_query_params_unsupported_param() {
        let params = json!({
            "unsupported": "value"
        });
        let result = ParameterFilter::validate_query_params(&params);
        assert!(matches!(result, Err(PolicyError::IncorrectFormatError(msg)) if msg.contains("Unsupported query parameter")));
    }

    #[test]
    fn test_validate_query_params_valid() {
        let params = json!({
            "ids": ["550e8400-e29b-41d4-a716-446655440000"],
            "attester_type": "type1"
        });
        let result = ParameterFilter::validate_query_params(&params);
        assert!(result.is_ok());
    }
}