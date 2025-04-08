use actix_web::{get, HttpResponse};
use crate::key_manager::secret_manager_factory::SecretManagerFactory;
use crate::key_manager::secret_manager_factory::SecretManagerType::OpenBao;

#[get("/ciphers")]
pub async fn get_ciphers() -> HttpResponse {
    let result = SecretManagerFactory::create_manager(OpenBao).get_all_secret();
    match result {
        Ok(private_key) => { HttpResponse::Ok().json(private_key)}
        Err(error) => { HttpResponse::BadRequest().body(error.to_string())}
    }
}