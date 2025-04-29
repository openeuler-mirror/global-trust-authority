use thiserror::Error;

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("incorrect format error {0}")]
    IncorrectFormatError(String),
}