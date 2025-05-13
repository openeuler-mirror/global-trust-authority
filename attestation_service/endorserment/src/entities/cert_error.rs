use thiserror::Error;

#[derive(Debug, Error)]
pub enum CertVerifyError {
    // Cert Verify Occur Database Error
    #[error("Cert verify occur database  error: {0}")]
    DbError(String),

    // Cert Verify Occur Verify Error
    #[error("Cert verify occur verify error: {0}")]
    VerifyError(String),
}