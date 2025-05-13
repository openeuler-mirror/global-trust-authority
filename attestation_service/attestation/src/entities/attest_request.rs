use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};

#[derive(Deserialize, Serialize, Validate, Debug)]
pub struct AttestRequest {
    pub message: Option<String>,

    #[validate(length(min = 1, max = 50))]
    pub agent_version: String,

    #[validate(custom(function = "validate_nonce_type"))]
    pub nonce_type: Option<String>,

    #[validate(custom(function = "validate_user_nonce"))]
    pub user_nonce: Option<String>,

    #[validate(length(min = 1), custom(function = "validate_measurements"))]
    pub measurements: Vec<Measurement>,
}

#[derive(Deserialize, Serialize, Validate, Debug, Clone)]
pub struct Measurement {
    #[validate(length(min = 1, max = 255))]
    pub node_id: String,

    pub nonce: Option<Nonce>,

    pub attester_data: Option<serde_json::Value>,

    #[validate(length(min = 1), custom(function = "validate_evidences"))]
    pub evidences: Vec<Evidence>,
}

#[derive(Deserialize, Serialize, Validate, Debug, Clone)]
pub struct Nonce {
    pub iat: u64,
    pub value: String,
    pub signature: String,
}

#[derive(Deserialize, Serialize, Validate, Debug, Clone)]
pub struct Evidence {
    #[validate(length(min = 1, max = 255))]
    pub attester_type: String,

    pub evidence: serde_json::Value,

    #[validate(custom(function = "validate_policy_ids"), length(min = 1, max = 10))]
    pub policy_ids: Option<Vec<String>>,
}

fn validate_nonce_type(nonce_type: &str) -> Result<(), ValidationError> {
    let valid_types = ["ignore", "user", "default"];
    if !valid_types.contains(&nonce_type) {
        let mut err = ValidationError::new("invalid_nonce_type");
        err.message = Some(std::borrow::Cow::Owned("nonce_type must be one of: ignore, user, default".to_string()));
        return Err(err);
    }
    Ok(())
}

fn validate_user_nonce(user_nonce: &str) -> Result<(), ValidationError> {
    if user_nonce.len() < 64 || user_nonce.len() > 1024 {
        let mut err = ValidationError::new("length");
        err.message = Some(std::borrow::Cow::Owned("user_nonce length must be between 64 and 1024 bytes".to_string()));
        return Err(err);
    }

    if BASE64.decode(user_nonce).is_err() {
        let mut err = ValidationError::new("invalid_base64");
        err.message = Some(std::borrow::Cow::Owned("user_nonce must be base64 encoded".to_string()));
        return Err(err);
    }
    Ok(())
}

fn validate_measurements(measurements: &Vec<Measurement>) -> Result<(), ValidationError> {
    for measurement in measurements {
        if let Err(errors) = measurement.validate() {
            let mut err = ValidationError::new("invalid_measurement");
            err.message = Some(std::borrow::Cow::Owned(format!("Invalid measurement: {:?}", errors)));
            return Err(err);
        }
    }
    Ok(())
}

fn validate_evidences(evidences: &Vec<Evidence>) -> Result<(), ValidationError> {
    for evidence in evidences {
        if let Err(errors) = evidence.validate() {
            let mut err = ValidationError::new("invalid_evidence");
            err.message = Some(std::borrow::Cow::Owned(format!("Invalid evidence: {:?}", errors)));
            return Err(err);
        }
    }
    Ok(())
}

fn validate_policy_ids(policy_ids: &Vec<String>) -> Result<(), ValidationError> {
    for policy_id in policy_ids {
        if policy_id.len() > 36 || policy_id.is_empty() {
            let mut err = ValidationError::new("length");
            err.message =
                Some(std::borrow::Cow::Owned("policy_id length must be between 1 and 36 characters".to_string()));
            return Err(err);
        }
    }
    Ok(())
}
