use actix_web::HttpResponse;
use log::{error, info};
use nonce::Nonce;
use mq::send_message;

// User Controller Layer
// Get all users
const RA_TOPIC :&str = "ra_topic";
pub async fn get_all_users() -> HttpResponse {
    // test kafka
    {
        send_message(RA_TOPIC, "test key", "message test....").await;
        info!("send message success!");
    }
    HttpResponse::Ok().body("TEST OK".to_string())
}

pub async fn get_nonce() -> HttpResponse {
    log::error!("test get_nonce.");
    let nonce = Nonce::generate().await;
    let iat1 = nonce::get_system_time();
    error!(
        "test redis begin=======iat ={}--value = {},---signature=",
        nonce.iat, nonce.value
    );

    let input = nonce::ValidateNonceParams {
        valid_period: iat1,
        nonce: nonce,
    };
    error!("input is {:?}", input);
    let res = nonce::validate_nonce(input).await;
    error!("res is  {},---{}", res.is_valid, res.message);
    HttpResponse::Ok().body("get_nonce ok".to_string())
}
