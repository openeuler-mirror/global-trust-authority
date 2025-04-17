use actix_web::{get, HttpResponse};
use crate::key_manager::secret_manager_factory::SecretManagerFactory;
use crate::key_manager::secret_manager_factory::SecretManagerType::OpenBao;
use crate::utils::errors::AppError;

#[get("/ciphers")]
pub async fn get_ciphers() -> Result<HttpResponse, AppError> {
    let result = SecretManagerFactory::create_manager(OpenBao).get_all_secret()?;
    Ok(HttpResponse::Ok().json(result))
}
