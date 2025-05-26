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
use std::collections::HashMap;
use log::info;

pub struct RvRedisRepo {}

impl RvRedisRepo {
    pub async fn batch_insert(models: Vec<RvRedisModel>) -> Result<(), RefValueError> {
        let cli = RedisClient::get_instance().map_err(|e| RefValueError::DbError(e.to_string()))?;
        let mut conn = cli.get_async_connection().await.map_err(|e| RefValueError::DbError(e.to_string()))?;
        let mut pipe = redis::pipe();

        for model in models {
            let key = model.user_id.clone() + ":" + &model.attester_type + ":" + &model.sha256;
            // 存储主数据
            pipe.hset_multiple(
                key,
                &[
                    ("file_name", &model.file_name),
                    ("user_id", &model.user_id),
                    ("attester_type", &model.attester_type),
                    ("rv_id", &model.rv_id),
                    ("sha256", &model.sha256),
                ],
            )
                // 建立索引
                .sadd(format!("idx:user:{}", model.user_id), &model.sha256)
                .sadd(format!("idx:type:{}", model.attester_type), &model.sha256)
                .sadd(format!("idx:rv:{}", model.rv_id), &model.sha256);
        }
        pipe.query_async(&mut conn).await.map_err(|e| RefValueError::DbError(e.to_string()))?;

        Ok(())
    }

    pub async fn query_by_user_and_type(
        sha256_list: Vec<String>,
        user_id: &str,
        attester_type: &str,
    ) -> Result<Vec<String>, RefValueError> {
        let cli = RedisClient::get_instance().map_err(|e| RefValueError::DbError(e.to_string()))?;
        let mut conn = cli.get_async_connection().await.map_err(|e| RefValueError::DbError(e.to_string()))?;
        let mut pipe = redis::pipe();


        // 1. 构建批量查询管道
        for key in &sha256_list {
            let act_key = user_id.to_string() + ":" + &attester_type + ":" + key;
            pipe.hget(act_key, "sha256");
        }
        let values: Vec<Option<String>> = pipe.query_async(&mut conn).await
            .map_err(|e| RefValueError::DbError(e.to_string()))?;
        
        // 3. 反序列化结果
        let mut result = Vec::new();
        
        for value in values {
            if let Some(exist_sha256) = value{
                result.push(exist_sha256);
            }
        }

        Ok(result)
    }

    pub async fn batch_delete_by_rv_id(rv_ids: Vec<String>) -> Result<(), RefValueError> {
        for rv_id in rv_ids {
            // 1. 获取所有关联 ID（通过反向索引）
            Self::delete_by_index(format!("idx:rv:{}", rv_id)).await?;
        }

        Ok(())
    }

    pub async fn delete_by_user_id(user_id: &str) -> Result<(), RefValueError> {
        Self::delete_by_index(format!("idx:user:{}", user_id)).await
    }

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

        // 获取所有文件的关联索引信息
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

        // 批量删除操作
        let mut pipe = redis::pipe();
        // 删除主数据
        for key in rvs {
            pipe.del(key);
        }
        // 清理所有索引
        for (uid, t, r) in &indices {
            pipe.srem(format!("idx:user:{}", uid), rvs);
            pipe.srem(format!("idx:type:{}", t), rvs);
            pipe.srem(format!("idx:rv:{}", r), rvs);
        }
        pipe.query_async(conn).await.map_err(|e| RefValueError::DbError(e.to_string()))?;

        Ok(())
    }

    fn hash_to_file(sha256: &str, data: HashMap<String, String>) -> RvRedisModel {
        RvRedisModel {
            sha256: sha256.to_string(),
            file_name: data.get("file_name").cloned().unwrap_or_default(),
            user_id: data.get("user_id").cloned().unwrap_or_default(),
            attester_type: data.get("attester_type").cloned().unwrap_or_default(),
            rv_id: data.get("rv_id").cloned().unwrap_or_default(),
        }
    }
}
