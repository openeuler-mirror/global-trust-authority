/// Plugin trait definitions

use async_trait::async_trait;
use serde_json::Value;
use thiserror::Error;
use std::result::Result;

/// Management trait - shared by all plugins
#[async_trait]
pub trait PluginBase: Send + Sync {
    fn plugin_type(&self) -> &str;
}

#[async_trait]
pub trait ServicePlugin: PluginBase {
    fn get_sample_output(&self) -> Value;
    async fn verify_evidence(&self, user_id: &str, node_id: Option<&str>, evidence: &Value, nonce: Option<&[u8]>) -> Result<Value, PluginError>;
}

pub trait AgentPlugin: PluginBase {
    fn collect_evidence(&self, node_id: Option<&str>, nonce: Option<&[u8]>) -> Result<Value, PluginError>;
}

/// Trait for getting singleton instances of plugin managers
pub trait PluginManagerInstance {
    fn get_instance() -> &'static Self;
}

#[derive(Error, Debug)]
pub enum PluginError {
    #[error("Input error: {0}")]
    InputError(String),
    
    #[error("Internal error: {0}")]
    InternalError(String),
}
