use mq::create_topic;

pub async fn create_mq_topics() {
    create_topic("ra_topic", 1, 1).await.expect("create topic failed, please check!");
}
