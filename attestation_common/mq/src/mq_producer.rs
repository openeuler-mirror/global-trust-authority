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

use log::{error, info};
use rdkafka::{
    config::ClientConfig,
    producer::{FutureProducer, FutureRecord},
};
use std::time::Duration;
use env_config_parse::env_parse::get_env_value;

pub async fn send_message(topic: &str, key: &str, payload: &str) {
    // 1. create producer
    let Ok(producer): Result<FutureProducer, _> = ClientConfig::new()
        .set("bootstrap.servers", get_env_value("MQ_HOST").await)
        .set("message.timeout.ms", "30000")
        .set("queue.buffering.max.messages", "100000")
        .set("compression.type", "snappy")
        .create() // auto config FutureProducer type
    else {
        error!("Failed to create Kafka producer");
        return;
    };

    let base_record = FutureRecord::to(topic).key(key);
    let payload = payload.to_owned(); // clone payload str
    
    let record = base_record.payload(&payload);
    match producer.send(record, Duration::from_secs(0)).await {
        Ok(delivery) => {
            info!("Message sent to partition {} offset {}",delivery.0, delivery.1);
        }
        Err((e, _original_record)) => {
            error!("send message failed, _original_record: {}", e);
        }
    }
}