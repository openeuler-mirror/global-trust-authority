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

use crate::init_chain::traits::{InitContext, InitHandler};

#[derive(Debug)]
pub struct  InitChain {
    first_handler: Option<Box<dyn InitHandler>>,
}

impl InitChain {
    /// Executes the initialization chain by running each handler in sequence
    ///
    /// # Arguments
    /// * `context` - Mutable reference to the initialization context
    ///
    /// # Returns
    /// * `Ok(())` - If all handlers execute successfully
    ///
    /// # Errors
    /// Returns `String` error when:
    /// * Any handler in the chain fails to execute
    /// * A handler returns an error during its execution
    pub async fn execute(&self, context: &mut InitContext) -> Result<(), String> {
        if let Some(handler) = &self.first_handler {
            handler.handle(context).await
        } else {
            Ok(())
        }
    }
}

impl InitChain {
    pub fn builder() -> InitChainBuilder {
        InitChainBuilder::new()
    }
}

pub struct InitChainBuilder {
    handlers: Vec<Box<dyn InitHandler>>,
}

impl InitChainBuilder {
    pub fn new() -> Self {
        InitChainBuilder {
            handlers: Vec::new(),
        }
    }

    pub fn add_handler<H: InitHandler + 'static>(mut self, handler: H) -> Self {
        self.handlers.push(Box::new(handler));
        self
    }

    pub fn build(mut self) -> InitChain {
        if self.handlers.is_empty() {
            return InitChain { first_handler: None };
        }
        // Add logic here to link handlers

        // Link handlers from back to front
        for i in (0..self.handlers.len().saturating_sub(1)).rev() {
            let next = self.handlers.remove(i + 1);
            if let Some(current) = self.handlers.get_mut(i) {
                current.set_next(next);
            }
        }

        InitChain {
            first_handler: Some(self.handlers.remove(0)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use super::*;

    #[derive(Debug)]
    struct TestHandler {
        name: String,
        next: Option<Box<dyn InitHandler>>,
        should_fail: bool,
        call_count: AtomicUsize,
    }

    impl TestHandler {
        fn new(name: &str, should_fail: bool) -> Self {
            TestHandler {
                name: name.to_string(),
                next: None,
                should_fail,
                call_count: AtomicUsize::new(0),
            }
        }


        async fn do_something(&self) -> Result<(), String>{
            if self.should_fail {
                Err(format!("Handler {} failed", self.name))
            } else {
                println!("Handler {} executed", self.name);
                Ok(())
            }
        }
    }

    impl InitHandler for TestHandler {
        fn handle<'a>(&'a self, context: &'a mut InitContext) -> Pin<Box<dyn Future<Output = Result<(), String>> + 'a>> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                self.do_something().await?;
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


    #[tokio::test]
    async fn test_empty_chain() {
        let chain = InitChain::builder().build();
        let mut context = InitContext::new();

        let result = chain.execute(&mut context).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_single_handler_chain() {
        let handler = TestHandler::new("handler1", false);
        let chain = InitChain::builder()
            .add_handler(handler)
            .build();

        let mut context = InitContext::new();
        let result = chain.execute(&mut context).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_multiple_handlers_chain() {
        let handler1 = TestHandler::new("handler1", false);
        let handler2 = TestHandler::new("handler2", false);
        let handler3 = TestHandler::new("handler3", false);

        let chain = InitChain::builder()
            .add_handler(handler1)
            .add_handler(handler2)
            .add_handler(handler3)
            .build();

        let mut context = InitContext::new();
        let result = chain.execute(&mut context).await;
        assert!(result.is_ok());
    }
}