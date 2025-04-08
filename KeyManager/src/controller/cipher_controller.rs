use actix_web::{get, HttpResponse};
use crate::key_manager::openbao_service::get_all_private_key;

#[get("/ciphers")]
pub async fn get_ciphers() -> HttpResponse {
    let result = get_all_private_key();
    match result {
        Ok(private_key) => { HttpResponse::Ok().json(private_key)}
        Err(error) => { HttpResponse::ServiceUnavailable().body(error.to_string())}
    }
}