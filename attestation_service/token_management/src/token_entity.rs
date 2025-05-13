use jsonwebtoken::Header;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// verify token response
#[derive(Serialize, Deserialize, Debug)]
pub struct VerifyTokenResponse {
    verification_pass: bool,
    token_body: Value,
    token_header: Header
}

impl VerifyTokenResponse {
    pub fn new(verification_pass: bool, token_body: Value, token_header: Header) -> Self {
        Self { verification_pass, token_body, token_header }
    }
}