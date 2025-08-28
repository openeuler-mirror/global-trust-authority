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
use kafka::producer::{Producer, Record, RequiredAcks};
use std::time::Duration;
use env_config_parse::env_parse::get_env_value;
use tokio::task;

pub async fn send_message(topic: &str, key: &str, payload: &str) {
    // obtain broker list from env
    let brokers = get_env_value("MQ_HOST").await;
    let brokers_list: Vec<String> = brokers
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if brokers_list.is_empty() {
        error!("MQ_HOST is empty, cannot create Kafka producer");
        return;
    }

    let topic_owned = topic.to_owned();
    let key_bytes = key.as_bytes().to_vec();
    let payload_bytes = payload.as_bytes().to_vec();

    let res = task::spawn_blocking(move || -> Result<(), kafka::error::Error> {
        // create synchronous Producer and configure
        let mut producer = Producer::from_hosts(brokers_list)
            .with_ack_timeout(Duration::from_secs(1))
            .with_required_acks(RequiredAcks::One)
            .create()?;

        // send message with key
        producer.send(&Record::from_key_value(&topic_owned, key_bytes.as_slice(), payload_bytes.as_slice()))
    })
    .await;

    match res {
        Ok(Ok(())) => {
            info!("Message sent to topic [{}]", topic);
        }
        Ok(Err(e)) => {
            error!("send message failed: {}", e);
        }
        Err(e) => {
            error!("spawn_blocking join error: {}", e);
        }
    }
}