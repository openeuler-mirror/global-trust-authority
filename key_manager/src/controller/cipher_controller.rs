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

use actix_web::{get, HttpResponse, ResponseError};
use crate::key_manager::secret_manager_factory::SecretManagerFactory;
use crate::key_manager::secret_manager_factory::SecretManagerType::OpenBao;

#[get("/v1/vault/get_signing_keys")]
pub async fn get_ciphers() -> HttpResponse {
    match SecretManagerFactory::create_manager(OpenBao).get_all_secret().await {
        Ok(ciphers) => HttpResponse::Ok().json(ciphers),
        Err(err) => err.error_response()
    }
}
