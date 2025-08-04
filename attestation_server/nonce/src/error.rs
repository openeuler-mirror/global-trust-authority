use thiserror::Error;

#[derive(Error, Debug)]
pub enum NonceError {
    #[error("Failed to generate random number.")]
    RngError,
    
    #[error("Failed to generate signature.")]
    SignatureError,
}