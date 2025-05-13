use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct PolicyAddRequest {
    #[validate(length(min = 1, max = 255), custom(function = "validate_string"))]
    pub name: String,

    #[validate(length(max = 512), custom(function = "validate_string"))]
    pub description: Option<String>,

    #[validate(length(min = 1), custom(function = "validate_attester_type"))]
    pub attester_type: Vec<String>,

    #[validate(custom(function = "validate_content_type"))]
    pub content_type: String,

    #[validate(length(min = 1))]
    pub content: String,

    pub is_default: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct PolicyUpdateRequest {
    #[validate(length(min = 1, max = 36), custom(function = "validate_string"))]
    pub id: String,

    #[validate(length(min = 1, max = 255), custom(function = "validate_string"))]
    pub name: Option<String>,

    #[validate(length(max = 512), custom(function = "validate_string"))]
    pub description: Option<String>,

    #[validate(length(min = 1), custom(function = "validate_attester_type"))]
    pub attester_type: Option<Vec<String>>,

    #[validate(custom(function = "validate_content_type"))]
    pub content_type: Option<String>,

    #[validate(length(min = 1))]
    pub content: Option<String>,

    pub is_default: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct PolicyDeleteRequest {
    #[validate(custom(function = "validate_delete_type"))]
    pub delete_type: String,

    #[validate(length(max = 10), custom(function = "validate_ids"))]
    pub ids: Option<Vec<String>>,

    #[validate(length(max = 255), custom(function = "validate_string"))]
    pub attester_type: Option<String>,
}

fn validate_delete_type(delete_type: &str) -> Result<(), ValidationError> {
    match delete_type {
        "id" | "attester_type" | "all" => Ok(()),
        _ => Err(ValidationError::new("invalid_delete_type")),
    }
}

fn validate_content_type(content_type: &str) -> Result<(), ValidationError> {
    match content_type {
        "jwt" | "text" => Ok(()),
        _ => Err(ValidationError::new("invalid_content_type")),
    }
}

fn validate_attester_type(attester_type: &Vec<String>) -> Result<(), ValidationError> {
    if attester_type.is_empty() {
        return Err(ValidationError::new("attester_type_empty"));
    }

    for item in attester_type {
        if item.is_empty() || item.len() > 255 {
            return Err(ValidationError::new("invalid_attester_type_length"));
        }
        if let Err(_) = validate_string(item) {
            return Err(ValidationError::new("attester_type_contains_special_chars"));
        }
    }
    Ok(())
}

fn validate_ids(ids: &Vec<String>) -> Result<(), ValidationError> {
    if ids.is_empty() {
        return Err(ValidationError::new("ids_empty"));
    }

    for id in ids {
        if id.is_empty() || id.len() > 36 {
            return Err(ValidationError::new("invalid_id_length"));
        }
        if let Err(_) = validate_string(id) {
            return Err(ValidationError::new("id_contains_special_chars"));
        }
    }
    Ok(())
}

fn validate_string(name: &str) -> Result<(), ValidationError> {
    let special_chars = ['<', '>', '"', '\'', '&', '|', '\\', '/', '*', '?', '`'];
    if name.chars().any(|c| special_chars.contains(&c)) {
        return Err(ValidationError::new("name_contains_special_chars"));
    }
    Ok(())
}
