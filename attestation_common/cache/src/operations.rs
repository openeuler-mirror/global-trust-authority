use std::ops::{Deref, DerefMut};
use std::time::Duration;
use redis::Commands;
use crate::client::RedisClient;
use crate::error::RedisError;

impl RedisClient {
    pub fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> Result<(), RedisError> {
        let mut conn = self.client.get_connection()
            .map_err(RedisError::ConnectionError)?;
        if let Some(ttl) = ttl {
            conn.set_ex(key, value, ttl.as_secs() as usize)
                .map_err(RedisError::ConnectionError)?
        } else {
            conn.set(key, value)
                .map_err(RedisError::ConnectionError)?
        }

        Ok(())
    }

    pub fn get(&self, key: &str) -> Result<String, RedisError> {
        let mut conn = self.client.get_connection()
            .map_err(RedisError::ConnectionError)?;
        let value: String = conn.get(key)
            .map_err(|e| match e.kind() {
                redis::ErrorKind::TypeError => RedisError::KeyNotFound,
                _ => RedisError::ConnectionError(e)
            })?;
        Ok(value)
    }

    pub fn del(&self, key: &str) -> Result<(), RedisError> {
        let mut conn = self.client.get_connection()
            .map_err(RedisError::ConnectionError)?;
        conn.del(key)
            .map_err(RedisError::ConnectionError)
    }

    pub fn exists(&self, key: &str) -> Result<bool, RedisError> {
        let mut conn = self.client.get_connection()
            .map_err(RedisError::ConnectionError)?;
        conn.exists(key)
            .map_err(RedisError::ConnectionError)
    }

    pub fn expire(&self, key: &str, ttl: Duration) -> Result<bool, RedisError> {
        let mut conn = self.client.get_connection()
            .map_err(RedisError::ConnectionError)?;
        conn.expire(key, ttl.as_secs() as usize)
            .map_err(RedisError::ConnectionError)
    }

    pub fn ttl(&self, key: &str) -> Result<i64, RedisError> {
        let mut conn = self.client.get_connection()
            .map_err(RedisError::ConnectionError)?;
        conn.ttl(key)
            .map_err(RedisError::ConnectionError)
    }

    pub fn set_nx(&self, key: &str, value: &str, ttl: Option<Duration>) -> Result<bool, RedisError> {
        let mut conn = self.client.get_connection()
            .map_err(RedisError::ConnectionError)?;
        let result = conn.set_nx(key, value)
            .map_err(RedisError::ConnectionError)?;
        
        if result && ttl.is_some() {
            conn.expire::<_, ()>(key, ttl.unwrap().as_secs() as usize)?;
        }
        
        Ok(result)
    }
}

impl Deref for RedisClient {
    type Target = redis::Client;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl DerefMut for RedisClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.client
    }
}