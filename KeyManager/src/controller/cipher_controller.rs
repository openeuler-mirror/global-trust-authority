use actix_web::{get, post, web, HttpResponse};
use crate::key_manager::secret_manager_factory::SecretManagerFactory;
use crate::key_manager::secret_manager_factory::SecretManagerType::OpenBao;
use crate::models::cipher_models::CreateCipherReq;
use crate::utils::response::{ApiResponse, AppError};

#[get("/ciphers")]
pub async fn get_ciphers() -> HttpResponse {
    let result = SecretManagerFactory::create_manager(OpenBao).get_all_secret();
    match result {
        Ok(private_key) => { HttpResponse::Ok().json(private_key)}
        Err(error) => { HttpResponse::BadRequest().body(error.to_string())}
    }
}

#[post("/ciphers")]
pub async fn create_ciphers(req: web::Json<CreateCipherReq>) -> Result<ApiResponse<String>, AppError> {
    SecretManagerFactory::create_manager(OpenBao).import_secret(&req)?;
    Ok(ApiResponse::ok_without_data())
}
