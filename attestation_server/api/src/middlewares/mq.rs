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

use config_manager::types::CONFIG;
use mq::check_topic;

pub async fn check_mq_topics() {
    if CONFIG.get_instance().unwrap().attestation_service.token_management.mq_enabled {
        check_topic(&CONFIG.get_instance().unwrap().attestation_service.token_management.token_topic)
            .await
            .expect("create topic failed, please check!");
    }
}
