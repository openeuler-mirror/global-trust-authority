use std::future::Future;
use mockall::automock;
use crate::key_manager::error::KeyManagerError;
use sea_orm::DatabaseTransaction;
use std::pin::Pin;
use std::sync::Arc;

pub(crate) type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

#[automock]
pub trait KeyLifecycleObserver: Send + Sync + std::fmt::Debug {
    fn signature_update(
        &self,
        key_version: &str,
        tx: Arc<DatabaseTransaction>,
    ) -> BoxFuture<Result<(), Box<KeyManagerError>>>;
}

#[allow(warnings)]
mod tests {
    use super::*;
    use std::fmt::Debug;
    use sea_orm::{DatabaseTransaction, DbBackend, MockDatabase, TransactionTrait};

    async fn mock_transaction() -> DatabaseTransaction  {
        let conn = MockDatabase::new(DbBackend::MySql).into_connection();
        conn.begin().await.unwrap()
    }

    #[derive(Debug)]
    struct MockKeyLifecycleObserver {}

    impl KeyLifecycleObserver for MockKeyLifecycleObserver {
        fn signature_update(&self, key_version: &str, tx: Arc<DatabaseTransaction>) -> BoxFuture<Result<(), Box<KeyManagerError>>> {
            Box::pin(async move {
                Ok(())
            })
        }
    }

    #[test]
    fn test_signature_update() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let mock = MockKeyLifecycleObserver {};
            let mock_tx = Arc::new(mock_transaction().await);
            assert!(MockKeyLifecycleObserver::signature_update(&mock, "v1", mock_tx).await.is_ok());
        })
    }
}
