use actix_web::{get, HttpRequest, HttpResponse, Responder};

#[get("/ciphers")]
pub async fn get_ciphers(req: HttpRequest) -> impl Responder {
    "Hello world"
}