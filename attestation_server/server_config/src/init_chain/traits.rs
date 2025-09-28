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

use config_manager::types::context::ServerConfig;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;

pub trait InitHandler: Debug {
    fn handle<'a>(&'a self, context: &'a mut InitContext) -> Pin<Box<dyn Future<Output = Result<(), String>> + 'a>>;
    fn set_next(&mut self, next: Box<dyn InitHandler>);
}

#[derive(Debug)]
pub struct InitContext {
    // This can store data that needs to be shared in the initialization chain
    pub config: Option<ServerConfig>,
}

impl InitContext {
    pub fn new() -> Self {
        InitContext { config: None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[derive(Debug)]
    struct TestHandler {
        name: String,
        next: Option<Box<dyn InitHandler>>,
        should_fail: bool,
    }

    impl TestHandler {
        fn new(name: &str, should_fail: bool) -> Self {
            TestHandler { name: name.to_string(), next: None, should_fail }
        }

        async fn do_something(&self) -> Result<(), String> {
            if self.should_fail {
                println!("Handler {} failed", self.name);
                Err(format!("Handler {} failed", self.name))
            } else {
                println!("Handler {} executed", self.name);
                Ok(())
            }
        }
    }

    impl InitHandler for TestHandler {
        fn handle<'a>(
            &'a self,
            context: &'a mut InitContext,
        ) -> Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
            Box::pin(async move {
                let _result = self.do_something().await?;
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

    #[test]
    fn test_init_context_new() {
        let context = InitContext::new();
        assert!(context.config.is_none());
    }

    #[tokio::test]
    async fn test_single_handler() {
        let handler = TestHandler::new("test", false);
        let mut context = InitContext::new();
        let result = handler.handle(&mut context).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handler_chain() {
        let mut handler1 = TestHandler::new("handler1", false);
        let mut handler2 = TestHandler::new("handler2", false);
        let handler3 = TestHandler::new("handler3", false);

        handler2.set_next(Box::new(handler3));
        handler1.set_next(Box::new(handler2));

        let mut context = InitContext::new();
        let result = handler1.handle(&mut context).await;
        assert!(result.is_ok());
    }

    // Test failure scenarios in the Handler chain
    #[tokio::test]
    // #[should_panic]
    async fn test_handler_chain_failure() {
        let mut handler1 = TestHandler::new("handler1", false);
        let mut handler2 = TestHandler::new("handler2", false); // This one will fail
        let handler3 = TestHandler::new("handler3", true);

        handler2.set_next(Box::new(handler3));
        handler1.set_next(Box::new(handler2));

        let mut context = InitContext::new();
        let result = handler1.handle(&mut context).await;
        assert!(result.is_err());
    }
}
