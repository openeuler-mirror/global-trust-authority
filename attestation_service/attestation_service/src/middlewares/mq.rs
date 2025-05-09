use config_manager::types::CONFIG;
use mq::create_topic;

pub async fn create_mq_topics() {
    create_topic("ra_topic", 1, 1).await.expect("create topic failed, please check!");
    if CONFIG.get_instance().unwrap().attestation_service.token_management.mq_enabled {
        create_topic(&CONFIG.get_instance().unwrap().attestation_service.token_management.token_topic, 1, 1)
            .await
            .expect("create topic failed, please check!");
    }
}
