use key_management::key_manager::key_initialization::init_keys;
use std::future::Future;
use std::pin::Pin;
// key_management.rs
use crate::init_chain::traits::{InitContext, InitHandler};
use config_manager::types::context::ServerConfig;
use common_log::info;

#[derive(Debug)]
pub struct KeyManagementInitHandler {
    next: Option<Box<dyn InitHandler>>,
}

impl KeyManagementInitHandler {
    pub fn new() -> Self {
        KeyManagementInitHandler { next: None }
    }

    async fn init_keys(&self) -> Result<(), String> {
        info!("Initializing key management...");
        // init keys
        init_keys().await.unwrap();
        Ok(())
    }
}

impl InitHandler for KeyManagementInitHandler {
    fn handle<'a>(&'a self, context: &'a mut InitContext) -> Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
        Box::pin(async move {
            info!("Initializing keys...");
            self.init_keys().await.expect("Initializing key management failed");
            info!("Successfully initialized keys.");
            if let Some(next) = &self.next {
                next.handle(context).await
            } else {
                Ok(())
            }
        })
    }

    fn set_next(&mut self, next: Box<dyn InitHandler>) {
        self.next = Some(next);
    }
}