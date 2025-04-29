//! Distributed lock module, providing a distributed lock implementation based on Redis

pub mod client;
pub mod error;
pub mod lock;
pub mod scripts;
pub mod user_lock;

pub use error::{DistributedLockError, Result};
pub use lock::Lock;
pub use user_lock::UserLock;