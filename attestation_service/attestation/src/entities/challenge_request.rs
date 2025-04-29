use validator::{Validate, ValidationError};
use serde::Deserialize;

#[derive(Deserialize, Validate, Debug)]
pub struct ChallengeRequest {
    #[validate(length(min = 1, max = 50))]
    pub agent_version: String,

    #[validate(length(min = 1), custom(function = "validate_attester_type_elements"))]
    pub attester_type: Vec<String>,
}

fn validate_attester_type_elements(attester_type: &Vec<String>) -> Result<(), ValidationError> {
    for element in attester_type {
        if element.len() > 255 || element.len() == 0 {
            let mut err = ValidationError::new("length");
            err.message = Some(std::borrow::Cow::Owned("Element length more than 255 or equal to 0".to_string()));
            return Err(err);
        }
    }
    Ok(())
}
