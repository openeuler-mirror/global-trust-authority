use std::sync::Arc;
#[cfg(feature = "mysql_mode")]
use crate::services::mysql_mode;
#[cfg(feature = "redis_mode")]
use crate::services::redis_mode;
use crate::services::rv_trait::RefValueTrait;

pub struct RvFactory;

impl RvFactory {
    #[cfg(feature = "mysql_mode")]
    pub fn create_ref_value() -> Arc<impl RefValueTrait> {
        Arc::new(mysql_mode::rv_mysql_impl::RvMysqlImpl::new())
    }

    #[cfg(feature = "redis_mode")]
    pub fn create_ref_value() -> Arc<impl RefValueTrait> {
        Arc::new(redis_mode::rv_redis_impl::RvRedisImpl::new())
    }
}
