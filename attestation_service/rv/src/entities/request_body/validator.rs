use validator::ValidationError;

pub struct Validator {}

impl Validator {
    pub fn validate_ids_could_not_none(ids: &Option<Vec<String>>) -> Result<(), ValidationError> {
        match &ids {
            Some(ids) => {
                Self::validate_ids(ids)
            }
            None => {
                Err(ValidationError::new("invalid ids, ids should not be None"))
            }
        }
    }
    
    pub fn validate_ids_could_none(ids: &Option<Vec<String>>) -> Result<(), ValidationError> {
        if let Some(ids) = ids {
            return Self::validate_ids(ids);
        }
        Ok(())
    }
    
    fn validate_ids(ids: &Vec<String>) -> Result<(), ValidationError> {
        if ids.len() <= 0 || ids.len() > 10 {
            return Err(ValidationError::new("invalid ids, ids should be between 0 and 10"));
        }
        Ok(())
    }

    pub fn validate_attester_type_could_none(attester_type: &Option<String>) -> Result<(), ValidationError> {
        if let Some(attester_type) = attester_type {
            return Self::validate_attester_type(attester_type);
        }
        Ok(())
    }

    pub fn validate_attester_type_could_not_none(attester_type: &Option<String>) -> Result<(), ValidationError> {
        match &attester_type {
            Some(attester_type) => {
                Self::validate_attester_type(attester_type)
            }
            None => {
                Err(ValidationError::new("invalid attester_type, attester_type should not be None"))
            }
        }
    }
    
    fn validate_attester_type(attester_type: &str) -> Result<(), ValidationError> {
        let allowed_attester_types = vec!["tpm_ima"];
        if !allowed_attester_types.contains(&attester_type) {
            let mut error = ValidationError::new("invalid_attester_type")
                .with_message(
                    format!("Unsupported attester type: `{}`", attester_type).into()
                );
            error.add_param("allowed_types".into(), &allowed_attester_types);
            return Err(error)
        }
        Ok(())
    }
}