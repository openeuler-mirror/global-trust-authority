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

use crate::entities::db_model::rv_dtl_redis_model::RvRedisModel;
use crate::error::ref_value_error::RefValueError;
use cache::client::RedisClient;
use redis;
use redis::AsyncCommands;

pub struct RvRedisRepo {}

impl RvRedisRepo {
    pub async fn batch_insert(models: Vec<RvRedisModel>) -> Result<(), RefValueError> {
        let cli = RedisClient::get_instance().map_err(|e| RefValueError::DbError(e.to_string()))?;
        let mut conn = cli.get_async_connection().await.map_err(|e| RefValueError::DbError(e.to_string()))?;
        let mut pipe = redis::pipe();

        for model in models {
            let key = model.user_id.clone() + ":" + &model.attester_type + ":" + &model.sha256;
            pipe.hset_multiple(
                key.clone(),
                &[
                    ("file_name", &model.file_name),
                    ("user_id", &model.user_id),
                    ("attester_type", &model.attester_type),
                    ("rv_id", &model.rv_id),
                    ("sha256", &model.sha256),
                ],
            )
                .sadd(format!("idx:user:{}", model.user_id), &key)
                .sadd(format!("idx:type:{}", model.attester_type), &key)
                .sadd(format!("idx:rv:{}", model.rv_id), &key);
        }
        pipe.query_async::<_, ()>(&mut conn).await.map_err(|e| RefValueError::DbError(e.to_string()))?;

        Ok(())
    }

    /// Queries reference values by user ID and attester type for a list of SHA256 hashes
    ///
    /// # Arguments
    /// * `sha256_list` - List of SHA256 hashes to query
    /// * `user_id` - User ID to filter by
    /// * `attester_type` - Attester type to filter by
    ///
    /// # Returns
    /// * `Ok(Vec<String>)` - List of matching SHA256 hashes found in Redis
    ///
    /// # Errors
    /// Returns `RefValueError` when:
    /// * `DbError` - Failed to get Redis client instance
    /// * `DbError` - Failed to establish Redis connection
    /// * `DbError` - Failed to execute query operations
    pub async fn query_by_user_and_type(
        sha256_list: Vec<String>,
        user_id: &str,
        attester_type: &str,
    ) -> Result<Vec<String>, RefValueError> {
        let cli = RedisClient::get_instance().map_err(|e| RefValueError::DbError(e.to_string()))?;
        let mut conn = cli.get_async_connection().await.map_err(|e| RefValueError::DbError(e.to_string()))?;
        let mut pipe = redis::pipe();


        for key in &sha256_list {
            let act_key = format!("{}:{}:{}", user_id, attester_type, key);
            pipe.hget(act_key, "sha256");
        }
        let values: Vec<Option<String>> = pipe.query_async(&mut conn).await
            .map_err(|e| RefValueError::DbError(e.to_string()))?;

        let mut result = Vec::new();
        
        for value in values {
            if let Some(exist_sha256) = value{
                result.push(exist_sha256);
            }
        }

        Ok(result)
    }

    /// Deletes multiple reference values by their reference value IDs
    ///
    /// # Arguments
    /// * `rv_ids` - Vector of reference value IDs to delete
    ///
    /// # Returns
    /// * `Ok(())` - If all reference values were successfully deleted
    ///
    /// # Errors
    /// Returns `RefValueError` when:
    /// * `DbError` - If there's an error connecting to Redis
    /// * `DbError` - If there's an error retrieving associated indices
    /// * `DbError` - If there's an error executing delete operations
    pub async fn batch_delete_by_rv_id(rv_ids: Vec<String>) -> Result<(), RefValueError> {
        for rv_id in rv_ids {
            Self::delete_by_index(format!("idx:rv:{}", rv_id)).await?;
        }

        Ok(())
    }

    /// Deletes all reference values associated with a specific user ID
    ///
    /// # Arguments
    /// * `user_id` - The ID of the user whose reference values should be deleted
    ///
    /// # Returns
    /// * `Ok(())` - If the deletion was successful
    /// 
    /// # Errors
    /// Returns `RefValueError` when:
    /// * `DbError` - If there's an error connecting to Redis or executing the delete operations
    pub async fn delete_by_user_id(user_id: &str) -> Result<(), RefValueError> {
        Self::delete_by_index(format!("idx:user:{}", user_id)).await
    }

    /// Deletes all reference values associated with a specific user ID and attester type
    ///
    /// # Arguments
    /// * `user_id` - The ID of the user whose reference values should be deleted
    /// * `attester_type` - The type of attester whose reference values should be deleted
    ///
    /// # Returns
    /// * `Ok(())` - If the deletion was successful
    /// 
    /// # Errors
    /// Returns `RefValueError` when:
    /// * `DbError` - If there's an error connecting to Redis
    /// * `DbError` - If there's an error executing the intersection operation
    /// * `DbError` - If there's an error executing the delete operations
    pub async fn delete_by_user_and_type(user_id: &str, attester_type: &str) -> Result<(), RefValueError> {
        let cli = RedisClient::get_instance().map_err(|e| RefValueError::DbError(e.to_string()))?;
        let mut conn = cli.get_async_connection().await.map_err(|e| RefValueError::DbError(e.to_string()))?;

        let files: Vec<String> = conn
            .sinter::<_, Vec<String>>(&[
                format!("idx:user:{}", user_id),
                format!("idx:type:{}", attester_type),
            ])
            .await.map_err(|e| RefValueError::DbError(e.to_string()))?;
        Self::delete_rv(&mut conn, &files).await
    }

    async fn delete_by_index(index_key: String) -> Result<(), RefValueError> {
        let cli = RedisClient::get_instance().map_err(|e| RefValueError::DbError(e.to_string()))?;
        let mut conn = cli.get_async_connection().await.map_err(|e| RefValueError::DbError(e.to_string()))?;

        let rvs: Vec<String> = conn.smembers(&index_key).await.map_err(|e| RefValueError::DbError(e.to_string()))?;
        Self::delete_rv(&mut conn, &rvs).await
    }

    async fn delete_rv(conn: &mut redis::aio::Connection, rvs: &[String]) -> Result<(), RefValueError> {
        if rvs.is_empty() {
            return Ok(());
        }

        let mut indices = Vec::new();
        for meas in rvs {
            let (user_id, attester_type, rv_id): (Option<String>, Option<String>, Option<String>) =
                redis::cmd("HMGET")
                    .arg(meas)
                    .arg("user_id")
                    .arg("attester_type")
                    .arg("rv_id")
                    .query_async(conn)
                    .await.map_err(|e| RefValueError::DbError(e.to_string()))?;

            if let (Some(uid), Some(t), Some(r)) = (user_id, attester_type, rv_id) {
                indices.push((uid, t, r));
            }
        }

        let mut pipe = redis::pipe();
        for key in rvs {
            pipe.del(key);
        }
        for (uid, t, r) in &indices {
            pipe.srem(format!("idx:user:{}", uid), rvs);
            pipe.srem(format!("idx:type:{}", t), rvs);
            pipe.srem(format!("idx:rv:{}", r), rvs);
        }
        pipe.query_async::<_, ()>(conn).await.map_err(|e| RefValueError::DbError(e.to_string()))?;

        Ok(())
    }
}
