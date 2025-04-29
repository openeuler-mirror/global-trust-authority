pub mod mq_config;

pub mod mq_producer;

pub use mq_config::create_topic;

pub use mq_producer::send_message;