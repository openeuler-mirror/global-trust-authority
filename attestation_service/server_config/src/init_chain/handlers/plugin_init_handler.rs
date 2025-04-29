use std::{future::Future, pin::Pin};

use common_log::info;
use plugin_manager::init_plugin::init_plugin;

use crate::init_chain::traits::{InitContext, InitHandler};


#[derive(Debug)]
pub struct PluginInitHandler {
    next: Option<Box<dyn InitHandler>>,
}

impl PluginInitHandler {
    pub fn new() -> PluginInitHandler {
        PluginInitHandler { next: None }
    }

    pub fn init_plugin(&self) {
        init_plugin().unwrap();
        info!("plugin initialized");
    }
}

impl InitHandler for PluginInitHandler {
    fn handle<'a>(&'a self, context: &'a mut InitContext) -> Pin<Box<dyn Future<Output=Result<(), String>> + 'a>> {
        Box::pin(async move {
            self.init_plugin();
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