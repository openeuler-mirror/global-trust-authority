/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 * Global Trust Authority is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

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
    let res = nonce::validate_nonce(input).await;
    HttpResponse::Ok().body("get_nonce ok".to_string())
}
