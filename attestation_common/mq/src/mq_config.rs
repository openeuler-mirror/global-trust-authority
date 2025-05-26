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
    admin::{AdminClient, AdminOptions, NewTopic, TopicReplication},
    client::DefaultClientContext,
    config::ClientConfig,
};
use env_config_parse::env_parse::get_env_value;

pub async fn create_topic(
    topic_name: &str,
    partitions: i32,
    replication: i32,
) -> Result<(), Box<dyn std::error::Error>> {
    let brokers = get_env_value("MQ_HOST").await;
    // create AdminClient
    let admin_client: AdminClient<DefaultClientContext> = ClientConfig::new()
        .set("bootstrap.servers", brokers)
        .create()?;

    // config Topic
    let new_topic = NewTopic::new(
        topic_name,
        partitions,
        TopicReplication::Fixed(replication),
    );

    // async create Topic
    let create_result = admin_client
        .create_topics(&[new_topic], &AdminOptions::new())
        .await?;

    // check create result
    for result in create_result {
        match result {
            Ok(_) => info!("Topic [{}] created", topic_name),
            Err(e) => {
                error!("Error creating topic: [{}], error : {}", e.0, e.1.to_string());
            }
        }
    }

    Ok(())
}