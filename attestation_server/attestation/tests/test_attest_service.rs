use actix_web::web;
use validator::Validate;

#[cfg(test)]
mod tests {
    use super::*;
    use attestation::entities::attest_request::AttestRequest;
    use attestation::error::attestation_error::AttestationError;
    use attestation::service::attest_service::AttestationService;

    fn setup() {
        let _ = common_log::init();
    }

    fn create_invalid_request() -> web::Json<AttestRequest> {
        web::Json(AttestRequest {
            message: None,
            agent_version: Option::from("".to_string()),
            nonce_type: Some("verifier".to_string()),
            user_nonce: None,
            measurements: vec![]
        })
    }

    #[tokio::test]
    async fn test_process_standard_attestation_invalid_request() {
        // Setup
        setup();

        // Arrange
        let request = create_invalid_request();
        let user_id = "test_user".to_string();

        // Act
        let result = AttestationService::process_default_attestation(&request, user_id).await;

        // Assert
        assert!(result.is_err());
        match result {
            Err(AttestationError::InvalidParameter(_)) => assert!(true),
            _ => assert!(false, "Expected InvalidParameter error"),
        }
    }
}