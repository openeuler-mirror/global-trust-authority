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
use kafka::client::KafkaClient;
use env_config_parse::env_parse::get_env_value;

pub async fn check_topic(
    topic_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let brokers = get_env_value("MQ_HOST").await;
    let brokers_list: Vec<String> = brokers
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if brokers_list.is_empty() {
        error!("MQ_HOST is empty, cannot connect to Kafka brokers");
        return Err("MQ_HOST is empty".into());
    }

    // Load metadata and check whether the topic exists
    let mut client = KafkaClient::new(brokers_list);
    if let Err(e) = client.load_metadata_all() {
        error!("Failed to load Kafka metadata: {}", e);
        return Err(Box::new(e));
    }

    let exists = client.topics().iter().any(|t| t.name() == topic_name);
    if exists {
        info!("Topic [{}] already exists", topic_name);
    } else {
        error!(
            "Topic [{}] not found. Please create the topic first.",
            topic_name
        );
    }

    Ok(())
}