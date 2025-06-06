use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use sea_orm::DatabaseConnection;
use common_log::info;
use rdb::{execute_sql_file, get_connection, DbError};
use crate::init_chain::traits::{InitContext, InitHandler};

#[derive(Debug)]
pub struct DbTableInitHandler {
    next: Option<Box<dyn InitHandler>>,
}

impl DbTableInitHandler {
    pub fn new() -> Self {
        Self {
            next: None
        }
    }

    async fn init_table(&self) -> Result<(), Box<dyn Error>> {
        info!("will init DB sql file!");
        let conn = get_connection().await?.clone();
        let db_version = "v1".to_string();
        execute_sql_file(&conn, &db_version).await
    }
}

impl InitHandler for DbTableInitHandler {
    fn handle<'a>(&'a self, context: &'a mut InitContext) -> Pin<Box<dyn Future<Output=Result<(), String>> + 'a>> {
        Box::pin(async move {
            println!("Initializing db tables...");
            self.init_table().await.expect("Initializing db table failed");
            println!("Successfully to init db tables.");
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