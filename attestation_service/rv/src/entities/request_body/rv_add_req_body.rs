use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};

#[derive(Clone, Deserialize, Validate, Serialize)]
pub struct RvAddReqBody {
    /// Reference value name
    #[validate(length(min = 1, max = 255))]
    pub name: String,

    /// Reference value description
    #[validate(length(max = 512))]
    pub description: Option<String>,

    /// challenge plugin type
    #[validate(custom(function = "validate_attester_type"))]
    pub attester_type: String,
    
    /// content
    #[validate(custom(function = "validate_content_max_size"))]
    pub content: String,

    /// is default reference value
    #[serde(default = "default_rv")]
    pub is_default: Option<bool>,
}

fn default_rv() -> Option<bool> {
    Option::from(true)
}

fn validate_attester_type(attester_type: &str) -> Result<(), ValidationError> {
    if attester_type.is_empty() {
        return Err(ValidationError::new("attester_type is empty"));
    }
    let allowed_attester_types = vec!["tpm_ima"];
    if !allowed_attester_types.contains(&attester_type) {
        let mut error = ValidationError::new("invalid_attester_type")
            .with_message(
                format!("Unsupported attester type: `{}`", attester_type).into()
            );
        error.add_param("allowed_types".into(), &allowed_attester_types);
        return Err(error);
    }
    Ok(())
}

fn validate_content_max_size(content: &str) -> Result<(), ValidationError> {
    if content.len() > 10 * 1024 * 1024 {
        return Err(ValidationError::new("content_max_size is too large"))
    }
    Ok(())
}
