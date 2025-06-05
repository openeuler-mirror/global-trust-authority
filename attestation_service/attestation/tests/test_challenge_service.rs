use actix_web::web;
use validator::Validate;

#[cfg(test)]
mod tests {
    use super::*;
    use attestation::entities::challenge_request::ChallengeRequest;
    use attestation::error::attestation_error::AttestationError;
    use attestation::service::challenge_service::ChallengeService;
    use common_log;

    fn setup() {
        let _ = common_log::init();
    }

    #[tokio::test]
    async fn test_generate_nonce_with_invalid_plugin() {
        // Setup environment
        setup();

        // Arrange
        let request = ChallengeRequest {
            agent_version: "1.0".to_string(),
            attester_type: vec!["INVALID_TYPE".to_string()]
        };
        let json_request = web::Json(request);

        // Act
        let result = ChallengeService::generate_nonce(json_request).await;

        // Assert
        assert!(result.is_err());
        match result.unwrap_err() {
            AttestationError::PluginNotFoundError(_) => assert!(true),
            err => panic!("Expected PluginNotFoundError, got {:?}", err),
        }
    }
}
