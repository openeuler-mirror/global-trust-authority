use actix_web::{get, HttpResponse, ResponseError};
use crate::key_manager::secret_manager_factory::SecretManagerFactory;
use crate::key_manager::secret_manager_factory::SecretManagerType::OpenBao;

#[get("/get_key")]
pub async fn get_ciphers() -> HttpResponse {
    match SecretManagerFactory::create_manager(OpenBao).get_all_secret().await {
        Ok(ciphers) => HttpResponse::Ok().json(ciphers),
        Err(err) => err.error_response()
    }
}
