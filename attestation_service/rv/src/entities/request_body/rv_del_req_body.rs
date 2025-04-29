use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};
use crate::entities::request_body::validator::Validator;

#[derive(Clone, Deserialize, Validate, Serialize)]
#[validate(schema(function = "validate_del_req_body"))]
pub struct RvDelReqBody {
    pub delete_type: String,
    
    pub ids: Option<Vec<String>>,
    
    pub attester_type: Option<String>,
}
fn validate_del_req_body(req_body: &RvDelReqBody) -> Result<(), ValidationError> {
    validate_delete_type(&req_body.delete_type)?;
    if req_body.delete_type == "id" {
        Validator::validate_ids_could_not_none(&req_body.ids)?;
    }
    if req_body.delete_type == "type" {
        Validator::validate_attester_type_could_not_none(&req_body.attester_type)?;
    }
    Ok(())
}

fn validate_delete_type(delete_type: &str) -> Result<(), ValidationError> {
    if delete_type.is_empty() {
        return Err(ValidationError::new("delete_type is empty"));
    }
    let delete_types = vec!["all", "id", "type"];
    if !delete_types.contains(&delete_type) {
        let mut error = ValidationError::new("invalid_delete_type")
            .with_message(
                format!("Unsupported delete type: `{}`", delete_type).into()
            );
        error.add_param("allowed_types".into(), &delete_types);
        return Err(error);
    }
    Ok(())
}