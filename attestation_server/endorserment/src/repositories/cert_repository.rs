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

use crate::entities::prelude::{CertInfo, CertRevokedList, CrlInfo};
use crate::entities::{cert_info, cert_revoked_list, crl_info};
use crate::services::cert_service;
use crate::services::cert_service::DeleteType;
use common_log::info;
use config_manager::types::CONFIG;
use sea_orm::sea_query::Expr;
use sea_orm::{ActiveModelTrait, ActiveValue, ColumnTrait, ConnectionTrait, DatabaseBackend, DatabaseConnection, DatabaseTransaction, DbErr, DeleteResult, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, Statement, TransactionTrait, UpdateResult};
use uuid::Uuid;

pub struct CertRepository;

impl CertRepository {
    /// Finds all certificates for a specific user, optionally filtered by IDs or certificate type.
    ///
    /// # Arguments
    /// * `db` - Database connection
    /// * `ids` - Optional vector of certificate IDs to filter by
    /// * `cert_type` - Optional certificate type to filter by
    /// * `user_id` - ID of the user whose certificates to retrieve
    ///
    /// # Returns
    /// * `Result<Vec<(cert_info::Model, Option<cert_revoked_list::Model>)>, DbErr>` - A vector of certificate models and their associated revoked list models if successful, or a database error.
    ///
    /// # Error
    /// * `DbErr` - If there is an error during the database operation.
    pub async fn find_all(
        db: &DatabaseConnection,
        ids: &Option<Vec<String>>,
        cert_type: &Option<String>,
        user_id: &str,
    ) -> Result<Vec<(cert_info::Model, Option<cert_revoked_list::Model>)>, DbErr> {
        info!("Fetching certs from database");
        // Build base query
        let mut query = CertInfo::find();

        match ids {
            Some(ids) => {
                query
                    .filter(cert_info::Column::Id.is_in(ids.clone()))
                    .filter(cert_info::Column::UserId.eq(user_id))
                    .find_also_related(CertRevokedList)
                    .order_by_desc(cert_info::Column::UpdateTime)
                    .all(db)
                    .await
            },
            None => {
                // If cert_type is not empty, add cert_type filter condition
                if let Some(cert_type) = cert_type {
                    query = query.filter(
                        cert_info::Column::UserId
                            .eq(user_id)
                            .and(Expr::cust(&format!("JSON_CONTAINS(type, '\"{}\"')", &cert_type))),
                    );
                } else {
                    query = query.filter(cert_info::Column::UserId.eq(user_id));
                }
                query
                    .select_only()
                    .column_as(cert_info::Column::Id, "id")
                    .column_as(cert_info::Column::Name, "name")
                    .column_as(cert_info::Column::Version, "version")
                    .order_by_desc(cert_info::Column::UpdateTime)
                    .into_model::<cert_info::SimpleInfo>()
                    .all(db)
                    .await
                    .map(|certs| {
                        certs
                            .into_iter()
                            .map(|c| {
                                (
                                    cert_info::Model {
                                        id: c.id,
                                        name: c.name,
                                        version: c.version,
                                        ..Default::default()
                                    },
                                    None,
                                )
                            })
                            .collect()
                    })
            },
        }
    }

    /// Verifies if a certificate name is duplicated for a given user, excluding a specific certificate ID.
    ///
    /// # Arguments
    /// * `db` - Database connection
    /// * `name` - Optional name of the certificate to check
    /// * `id` - Optional ID of the certificate to exclude from the check
    ///
    /// # Returns
    /// * `Result<bool, DbErr>` - True if the name is duplicated, false otherwise, or a database error.
    ///
    /// # Error
    /// * `DbErr` - If there is an error during the database operation.
    pub async fn verify_name_is_duplicated(
        db: &DatabaseConnection,
        name: Option<String>,
        id: Option<String>,
        user_id: &str,
    ) -> Result<bool, DbErr> {
        let mut query = CertInfo::find();
        if let Some(id) = id {
            query = query.filter(cert_info::Column::Id.ne(id));
        }
        let count = query.filter(cert_info::Column::Name.is_in(name.clone()))
            .filter(cert_info::Column::UserId.eq(user_id))
            .count(db).await;
        Ok(count? > 0)
    }

    /// Retrieves the CRL ID for a specific user and CRL name, generating a new one if it doesn't exist.
    ///
    /// # Arguments
    /// * `db` - Database connection
    /// * `user_id` - ID of the user
    /// * `name` - Name of the CRL
    ///
    /// # Returns
    /// * `Result<String, DbErr>` - The CRL ID if successful, or a database error.
    ///
    /// # Error
    /// * `DbErr` - If there is an error during the database operation.
    /// 
    /// # Panics
    /// * If there is an error generating a new CRL ID.
    pub async fn get_user_crl_id(db: &DatabaseConnection, user_id: &str, name: String) -> Result<String, DbErr> {
        let query = CrlInfo::find();
        let crl_info =
            query.filter(crl_info::Column::UserId.eq(user_id)).filter(crl_info::Column::Name.eq(name)).all(db).await?;
        if crl_info.is_empty() {
            return Ok(Uuid::new_v4().to_string());
        }
        let crl_info = crl_info.get(0).unwrap();
        Ok(crl_info.clone().crl_id)
    }

    /// Retrieves the number of CRLs for a specific user, excluding a given CRL name.
    ///
    /// # Arguments
    /// * `db` - Database connection
    /// * `user_id` - ID of the user
    /// * `name` - Name of the CRL to exclude from the count
    ///
    /// # Returns
    /// * `Result<u64, DbErr>` - The number of CRLs if successful, or a database error.
    ///
    /// # Error
    /// * `DbErr` - If there is an error during the database operation.
    pub async fn get_user_crl_num(db: &DatabaseConnection, user_id: &str, name: String) -> Result<u64, DbErr> {
        let query = CrlInfo::find();
        query.filter(crl_info::Column::UserId.eq(user_id)).filter(crl_info::Column::Name.ne(name)).count(db).await
    }

    /// Deletes CRL information and associated revoked certificates for specific CRL IDs and user within a transaction.
    ///
    /// # Arguments
    /// * `db` - Database transaction
    /// * `crl_ids` - Vector of CRL IDs to delete
    /// * `user_id` - ID of the user
    ///
    /// # Returns
    /// * `Result<DeleteResult, DbErr>` - The result of the delete operation if successful, or a database error.
    ///
    /// # Error
    /// * `DbErr` - If there is an error during the database operation.
    pub async fn delete_user_crl_by_ids(
        db: &DatabaseTransaction,
        crl_ids: Vec<String>,
        user_id: &str,
    ) -> Result<DeleteResult, DbErr> {
        let delete_result = CrlInfo::delete_many()
            .filter(crl_info::Column::UserId.eq(user_id))
            .filter(crl_info::Column::CrlId.is_in(crl_ids.clone()))
            .exec(db)
            .await?;
        CertRevokedList::delete_many()
            .filter(cert_revoked_list::Column::CrlId.is_in(crl_ids.clone()))
            .filter(cert_revoked_list::Column::UserId.eq(user_id))
            .exec(db)
            .await?;
        Ok(delete_result)
    }

    /// Deletes all CRL information and associated revoked certificates for a specific user within a transaction.
    ///
    /// # Arguments
    /// * `db` - Database transaction
    /// * `user_id` - ID of the user
    ///
    /// # Returns
    /// * `Result<DeleteResult, DbErr>` - The result of the delete operation if successful, or a database error.
    ///
    /// # Error
    /// * `DbErr` - If there is an error during the database operation.
    pub async fn delete_user_crl(db: &DatabaseTransaction, user_id: &str) -> Result<DeleteResult, DbErr> {
        let delete_result = CrlInfo::delete_many().filter(crl_info::Column::UserId.eq(user_id)).exec(db).await?;
        CertRevokedList::delete_many().filter(cert_revoked_list::Column::UserId.eq(user_id)).exec(db).await?;
        Ok(delete_result)
    }

    /// Inserts new CRL information into the database within a transaction.
    ///
    /// # Arguments
    /// * `db` - Database transaction
    /// * `crl_info` - Active model containing the CRL information to insert
    ///
    /// # Returns
    /// * `Result<(), DbErr>` - Ok if the insertion is successful, or a database error.
    ///
    /// # Error
    /// * `DbErr` - If there is an error during the database operation.
    pub async fn insert_crl_info(db: &DatabaseTransaction, crl_info: crl_info::ActiveModel) -> Result<(), DbErr> {
        crl_info.insert(db).await?;
        Ok(())
    }

    /// Queries CRL information by their IDs for a specific user.
    ///
    /// # Arguments
    /// * `db` - Database connection
    /// * `crl_ids` - Vector of CRL IDs to query
    /// * `user_id` - ID of the user
    ///
    /// # Returns
    /// * `Result<Vec<crl_info::Model>, DbErr>` - A vector of matching CRL models if successful, or a database error.
    ///
    /// # Error
    /// * `DbErr` - If there is an error during the database operation.
    pub async fn query_user_crl_info_by_ids(
        db: &DatabaseConnection,
        crl_ids: Vec<String>,
        user_id: &str,
    ) -> Result<Vec<crl_info::Model>, DbErr> {
        let query = CrlInfo::find();
        Ok(query
            .filter(crl_info::Column::UserId.eq(user_id))
            .filter(crl_info::Column::CrlId.is_in(crl_ids))
            .all(db)
            .await?)
    }

    /// Queries all CRL information for a specific user.
    ///
    /// # Arguments
    /// * `db` - Database connection
    /// * `user_id` - ID of the user
    ///
    /// # Returns
    /// * `Result<Vec<crl_info::Model>, DbErr>` - A vector of CRL models for the user if successful, or a database error.
    ///
    /// # Error
    /// * `DbErr` - If there is an error during the database operation.
    pub async fn query_user_crl_info(db: &DatabaseConnection, user_id: &str) -> Result<Vec<crl_info::Model>, DbErr> {
        let query = CrlInfo::find();
        Ok(query
            .filter(crl_info::Column::UserId.eq(user_id))
            .all(db)
            .await?)
    }

    async fn delete_crl_info(
        ids: Option<Vec<String>>,
        user_id: &str,
        db: &DatabaseConnection,
    ) -> Result<DeleteResult, DbErr> {
        let mut crl_ids: Vec<String> = Vec::new();
        if let Some(ids) = &ids {
            if ids.len() > CONFIG.get_instance().unwrap().attestation_service.cert.single_user_cert_limit as usize {
                return Err(DbErr::Custom("IDs exceed maximum limit".to_string()));
            }
            crl_ids = ids.clone();
        }
        let tx = db.begin().await?;
        let result = if crl_ids.is_empty() {
            Self::delete_user_crl(&tx, user_id).await
        } else {
            Self::delete_user_crl_by_ids(&tx, crl_ids.clone(), user_id).await
        };
        match result {
            Ok(result) => {
                tx.commit().await?;
                Ok(result)
            },
            Err(e) => {
                tx.rollback().await?;
                Err(e)
            },
        }
    }

    /// Retrieves the number of revoked certificates for a specific user.
    ///
    /// # Arguments
    /// * `db` - Database connection
    /// * `user_id` - ID of the user
    ///
    /// # Returns
    /// * `Result<u64, DbErr>` - The number of revoked certificates if successful, or a database error.
    ///
    /// # Error
    /// * `DbErr` - If there is an error during the database operation.
    pub async fn get_user_revoke_cert_num(db: &DatabaseConnection, user_id: &str) -> Result<u64, DbErr> {
        let query = CertRevokedList::find();
        query.filter(cert_revoked_list::Column::UserId.eq(user_id)).count(db).await
    }

    /// Calculates the total number of pages for a paginated query of certificates
    /// that do not match a specific key version.
    ///
    /// This is typically used for batch processing or synchronization tasks
    /// where certificates needing signature updates are retrieved in batches.
    ///
    /// # Arguments
    /// * `db` - Database transaction
    /// * `batch_size` - The number of items per page
    /// * `key_version` - The key version to exclude from the query
    ///
    /// # Returns
    /// * `Result<u64, DbErr>` - The total number of pages if successful, or a database error.
    ///
    /// # Error
    /// * `DbErr` - If there is an error during the database operation.
    pub async fn batch_get_all_certs_total_pages(
        db: &DatabaseTransaction,
        batch_size: u64,
        key_version: &str,
    ) -> Result<u64, DbErr> {
        let query = CertInfo::find();
        query
            .filter(cert_info::Column::KeyVersion.ne(key_version))
            .order_by_asc(cert_info::Column::Id)
            .find_also_related(CertRevokedList)
            .paginate(db, batch_size)
            .num_pages()
            .await
    }

    /// Retrieves a specific page of certificates that do not match a specific key version.
    ///
    /// This is used in conjunction with `batch_get_all_certs_total_pages` for
    /// batch processing or synchronization tasks.
    ///
    /// # Arguments
    /// * `db` - Database transaction
    /// * `page` - The page number to retrieve (0-indexed)
    /// * `batch_size` - The number of items per page
    /// * `key_version` - The key version to exclude from the query
    ///
    /// # Returns
    /// * `Result<Vec<cert_info::Model>, DbErr>` - A vector of certificate models for the requested page if successful, or a database error.
    ///
    /// # Error
    /// * `DbErr` - If there is an error during the database operation.
    pub async fn batch_get_certs(
        db: &DatabaseTransaction,
        page: u64,
        batch_size: u64,
        key_version: &str,
    ) -> Result<Vec<cert_info::Model>, DbErr> {
        let query = CertInfo::find();
        query
            .filter(cert_info::Column::KeyVersion.ne(key_version))
            .order_by_asc(cert_info::Column::Id)
            .paginate(db, batch_size)
            .fetch_page(page)
            .await
    }

    pub async fn batch_get_all_revoke_certs_total_pages(
        db: &DatabaseTransaction,
        batch_size: u64,
        key_version: &str,
    ) -> Result<u64, DbErr> {
        let query = CertRevokedList::find();
        query
            .filter(cert_revoked_list::Column::KeyVersion.ne(key_version))
            .order_by_asc(cert_revoked_list::Column::Id)
            .paginate(db, batch_size)
            .num_pages()
            .await
    }

    pub async fn batch_get_revoke_certs(
        db: &DatabaseTransaction,
        page: u64,
        batch_size: u64,
        key_version: &str,
    ) -> Result<Vec<cert_revoked_list::Model>, DbErr> {
        let query = CertRevokedList::find();
        query
            .filter(cert_revoked_list::Column::KeyVersion.ne(key_version))
            .order_by_asc(cert_revoked_list::Column::Id)
            .paginate(db, batch_size)
            .fetch_page(page)
            .await
    }

    /// Finds certificates for a specific user filtered by certificate type.
    ///
    /// This query uses a custom expression to filter based on the JSON `type` column.
    /// It also finds related revoked list entries.
    ///
    /// # Arguments
    /// * `db` - Database connection
    /// * `user_id` - ID of the user whose certificates to retrieve
    /// * `cert_type` - The certificate type to filter by (e.g., "refvalue", "policy")
    ///
    /// # Returns
    /// * `Result<Vec<(cert_info::Model, Option<cert_revoked_list::Model>)>, DbErr>` - A vector of matching certificate models and their associated revoked list models if successful, or a database error.
    ///
    /// # Error
    /// * `DbErr` - If there is an error during the database operation.
    pub async fn find_certs_by_type_and_user(
        db: &DatabaseConnection,
        user_id: &str,
        cert_type: &str,
    ) -> Result<Vec<(cert_info::Model, Option<cert_revoked_list::Model>)>, DbErr> {
        // Build base query
        let query = CertInfo::find();
        query
            .filter(
                cert_info::Column::UserId
                    .eq(user_id)
                    .and(Expr::cust(&format!("JSON_CONTAINS(type, '\"{}\"')", &cert_type))),
            )
            .find_also_related(CertRevokedList)
            .all(db)
            .await
    }

    /// Finds parent certificates for a specific user filtered by certificate type and issuer.
    ///
    /// This query uses a custom expression to filter based on the JSON `type` column
    /// and also filters by the `owner` column (representing the issuer).
    /// It also finds related revoked list entries.
    ///
    /// # Arguments
    /// * `db` - Database connection
    /// * `user_id` - ID of the user whose certificates to retrieve
    /// * `cert_type` - The certificate type to filter by (e.g., "refvalue", "policy")
    /// * `issuer` - The issuer (owner) of the parent certificate to filter by
    ///
    /// # Returns
    /// * `Result<Vec<(cert_info::Model, Option<cert_revoked_list::Model>)>, DbErr>` - A vector of matching certificate models and their associated revoked list models if successful, or a database error.
    ///
    /// # Error
    /// * `DbErr` - If there is an error during the database operation.
    pub async fn find_parent_cert_by_type_and_user(
        db: &DatabaseConnection,
        user_id: &str,
        cert_type: &str,
        issuer: &str,
    ) -> Result<Vec<(cert_info::Model, Option<cert_revoked_list::Model>)>, DbErr> {
        // Build base query
        let query = CertInfo::find();
        query
            .filter(
                cert_info::Column::UserId
                    .eq(user_id)
                    .and(Expr::cust(&format!("JSON_CONTAINS(type, '\"{}\"')", &cert_type))),
            )
            .filter(cert_info::Column::Owner.eq(issuer))
            .find_also_related(CertRevokedList)
            .all(db)
            .await
    }

    /// Finds a certificate by its unique ID.
    ///
    /// # Arguments
    /// * `db` - Database connection
    /// * `id` - The unique ID of the certificate to find.
    ///
    /// # Returns
    /// * `Result<Option<cert_info::Model>, DbErr>` - An optional certificate model if found,
    ///   `None` if not found, or a database error.
    ///
    /// # Error
    /// * `DbErr` - If there is an error during the database operation.
    pub async fn find_cert_by_id(db: &DatabaseConnection, id: &String) -> Result<Option<cert_info::Model>, DbErr> {
        CertInfo::find_by_id(id.to_string()).one(db).await
    }

    /// Deletes certificates for a specific user based on the specified deletion type.
    ///
    /// Supports deletion by a list of IDs, by certificate type, or deleting all certificates.
    /// Includes checks for ID limits and valid certificate types.
    ///
    /// # Arguments
    /// * `db` - Database connection
    /// * `delete_type` - The type of deletion to perform (`Id`, `Type`, or `All`).
    /// * `ids` - Optional vector of certificate IDs to delete (used with `DeleteType::Id`).
    /// * `cert_type` - Optional certificate type to delete (used with `DeleteType::Type`).
    /// * `user_id` - ID of the user whose certificates are being deleted.
    ///
    /// # Returns
    /// * `Result<DeleteResult, DbErr>` - The result of the delete operation if successful, or a database error.
    ///
    /// # Error
    /// * `DbErr` - If `delete_type` is `None`, if IDs are required but not provided,
    ///   if the number of IDs exceeds the limit, if `cert_type` is required but not provided,
    ///   if `cert_type` is invalid, or if there is an error during the database operation.
    pub async fn delete_certs(
        db: &DatabaseConnection,
        delete_type: Option<DeleteType>,
        ids: Option<Vec<String>>,
        cert_type: Option<String>,
        user_id: &str,
    ) -> Result<DeleteResult, DbErr> {
        if cert_type.clone().is_some() && cert_type.clone().unwrap() == "crl" {
            return Ok(Self::delete_crl_info(ids, user_id, db).await?);
        }
        if delete_type.is_none() {
            return Err(DbErr::Custom("Delete type is empty".to_string()));
        }
        match delete_type.unwrap() {
            DeleteType::Id => {
                // Check if there are more than 10 IDs
                if let Some(ids) = &ids {
                    if ids.len()
                        > CONFIG.get_instance().unwrap().attestation_service.cert.single_user_cert_limit as usize
                    {
                        return Err(DbErr::Custom("IDs exceed maximum limit of 10".to_string()));
                    }
                }
                if ids.is_none() {
                    return Err(DbErr::Custom("IDs not set".to_string()));
                }

                // Delete certificate information
                let cert_delete_result = CertInfo::delete_many()
                    .filter(cert_info::Column::Id.is_in(ids.clone().unwrap_or_default()))
                    .filter(cert_info::Column::UserId.eq(user_id))
                    .exec(db)
                    .await?;
                Ok(cert_delete_result)
            },
            DeleteType::Type => {
                // Check if the certificate type is legal
                let valid_types = [
                    cert_service::CertificateType::REFVALUE,
                    cert_service::CertificateType::POLICY,
                    cert_service::CertificateType::TPM_BOOT,
                    cert_service::CertificateType::TPM_IMA,
                ];
                if let Some(cert_type) = &cert_type {
                    if !valid_types.contains(&cert_type.as_str()) {
                        return Err(DbErr::Custom("Invalid certificate type".to_string()));
                    }
                }
                if cert_type.is_none() {
                    return Err(DbErr::Custom("certificate type not set".to_string()));
                }
                // Delete certificate information
                let cert_delete_result = CertInfo::delete_many()
                    .filter(
                        cert_info::Column::UserId
                            .eq(user_id)
                            .and(Expr::cust(&format!("JSON_CONTAINS(type, '\"{}\"')", cert_type.unwrap()))),
                    )
                    .exec(db)
                    .await?;
                Ok(cert_delete_result)
            },
            DeleteType::All => {
                // Delete all certificate information
                let cert_delete_result =
                    CertInfo::delete_many().filter(cert_info::Column::UserId.eq(user_id)).exec(db).await?;
                Ok(cert_delete_result)
            },
        }
    }

    /// Insert certificate information
    ///
    /// Inserts a new certificate record into the database. This method uses a custom SQL
    /// statement to handle database-specific logic, including checking for certificate
    /// count limits and ensuring the certificate name and ID are not duplicated
    /// before insertion.
    ///
    /// # Arguments
    /// * `db` - Database connection.
    /// * `cert_info` - The active model containing the certificate information to insert.
    /// * `cert_limit` - The maximum number of certificates allowed for the user.
    ///
    /// # Returns
    /// * `Result<u64, DbErr>` - The number of rows affected (should be 1 on success)
    ///   if the insertion is successful and passes the checks, or a database error.
    ///
    /// # Error
    /// * `DbErr` - If there is an error during the database operation, or if the
    ///   certificate count limit is exceeded, or if the name or ID is duplicated.
    pub async fn insert_cert_info(
        db: &DatabaseConnection,
        cert_info: cert_info::ActiveModel,
        cert_limit: u64,
    ) -> Result<u64, DbErr> {
        let id = cert_info.id.unwrap();
        let serial_num = cert_info.serial_num.unwrap();
        let user_id = cert_info.user_id.unwrap();
        let cert_type = cert_info.cert_type.unwrap();
        let name = cert_info.name.unwrap();
        let issuer = cert_info.issuer.unwrap();
        let owner = cert_info.owner.unwrap();
        let info = cert_info.cert_info.unwrap();
        let is_default = cert_info.is_default.unwrap();
        let description = cert_info.description.unwrap();
        let version = cert_info.version.unwrap();
        let create_time = cert_info.create_time.unwrap();
        let update_time = cert_info.update_time.unwrap();
        let signature = cert_info.signature.unwrap();
        let key_version = cert_info.key_version.unwrap();
        let valid_code = cert_info.valid_code.unwrap();

        let sql = Self::generate_add_cert_sql(db);

        let result = db
            .execute(Statement::from_sql_and_values(
                db.get_database_backend(),
                &sql,
                vec![
                    name.clone().into(),
                    user_id.clone().into(),
                    id.clone().into(),
                    user_id.clone().into(),
                    id.clone().into(),
                    serial_num.clone().into(),
                    user_id.clone().into(),
                    cert_type.into(),
                    name.into(),
                    issuer.into(),
                    owner.into(),
                    info.into(),
                    is_default.into(),
                    description.into(),
                    version.into(),
                    create_time.into(),
                    update_time.into(),
                    signature.into(),
                    key_version.into(),
                    valid_code.into(),
                    cert_limit.into(),
                ],
            ))
            .await?;
        Ok(result.rows_affected())
    }

    fn generate_add_cert_sql(db: &DatabaseConnection) -> String {
        match db.get_database_backend() {
            DatabaseBackend::MySql => String::from(
                r#"
                INSERT INTO t_cert_info (
                    id, serial_num, user_id, type,
                    name, issuer, owner, cert_info,
                    is_default, description, version, create_time, update_time,
                    signature, key_version, valid_code
                )
                WITH cert_checks AS (
                    SELECT
                        COUNT(*) as cert_count,
                        EXISTS(SELECT 1 FROM t_cert_info WHERE (name = ? and user_id = ?) or id = ?) as cert_exists
                    FROM t_cert_info
                    WHERE user_id = ?
                )
                SELECT
                    ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?
                FROM dual
                WHERE (SELECT cert_count FROM cert_checks) < ?
                AND (SELECT cert_exists FROM cert_checks) = false
                "#,
            ),
            DatabaseBackend::Postgres => String::from(
                r#"
                WITH cert_checks AS (
                    SELECT
                        COUNT(*) as cert_count,
                        EXISTS(SELECT 1 FROM t_cert_info WHERE (name = ? and user_id = ?) or id = ?) as cert_exists
                    FROM t_cert_info
                    WHERE user_id = ?
                )
                INSERT INTO t_cert_info (
                    id, serial_num, user_id, type,
                    name, issuer, owner, cert_info,
                    is_default, description, version, create_time, update_time,
                    signature, key_version, valid_code
                )
                SELECT
                    ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?
                WHERE (SELECT cert_count FROM cert_checks) < ?
                AND (SELECT cert_exists FROM cert_checks) = false
                "#,
            ),
            _ => panic!("Unsupported database backend"),
        }
    }

    /// Insert certificate revocation info
    pub async fn insert_cert_revoked(
        db: &DatabaseTransaction,
        cert_revoked: cert_revoked_list::ActiveModel,
    ) -> Result<(), DbErr> {
        cert_revoked.insert(db).await?;
        Ok(())
    }

    /// Update certificate info
    pub async fn update_cert_info(
        db: &DatabaseConnection,
        id: &String,
        version: i32,
        cert_info: cert_info::ActiveModel,
    ) -> Result<UpdateResult, DbErr> {
        let update_result: UpdateResult = CertInfo::update_many()
            .set(cert_info)
            .filter(cert_info::Column::Id.eq(id.as_str()))
            .filter(cert_info::Column::Version.eq(version))
            .exec(db)
            .await?;
        Ok(update_result)
    }

    pub async fn update_cert_info_when_signature_update(
        db: &DatabaseTransaction,
        id: &String,
        version: i32,
        cert_info: cert_info::ActiveModel,
    ) -> Result<UpdateResult, DbErr> {
        CertInfo::update_many()
            .set(cert_info)
            .filter(cert_info::Column::Id.eq(id.as_str()))
            .filter(cert_info::Column::Version.eq(version))
            .exec(db)
            .await
    }

    pub async fn update_revoke_cert_info(
        db: &DatabaseTransaction,
        id: &String,
        cert_revoked_list: cert_revoked_list::ActiveModel,
    ) -> Result<UpdateResult, DbErr> {
        let update_result: UpdateResult = CertRevokedList::update_many()
            .set(cert_revoked_list)
            .filter(cert_revoked_list::Column::Id.eq(id.as_str()))
            .exec(db)
            .await?;
        Ok(update_result)
    }

    pub async fn update_cert_valid_code(
        db: &DatabaseTransaction,
        id: &String,
        valid_code: Option<i32>,
    ) -> Result<cert_info::Model, DbErr> {
        let cert_info = cert_info::ActiveModel {
            id: ActiveValue::Set(id.to_string()),
            valid_code: ActiveValue::Set(valid_code),
            ..Default::default()
        };
        cert_info.update(db).await
    }

    pub async fn update_cert_revoked_valid_code(
        db: &DatabaseTransaction,
        id: &String,
        valid_code: Option<i32>,
    ) -> Result<cert_revoked_list::Model, DbErr> {
        let cert_revoked = cert_revoked_list::ActiveModel {
            id: ActiveValue::Set(id.to_string()),
            valid_code: ActiveValue::Set(valid_code),
            ..Default::default()
        };
        cert_revoked.update(db).await
    }
}

#[allow(unused_imports)]
use sea_orm::MockDatabase;

#[test]
fn test_generate_add_cert_sql_mysql() {
    let db = MockDatabase::new(DatabaseBackend::MySql).into_connection();
    let sql = CertRepository::generate_add_cert_sql(&db);

    // Verify MySQL SQL statement
    assert!(sql.contains("FROM dual"));
    assert!(sql.contains("INSERT INTO t_cert_info"));
    assert!(sql.contains("WITH cert_checks AS"));
    assert!(sql.contains("COUNT(*) as cert_count"));
    assert!(sql.contains("EXISTS(SELECT 1 FROM t_cert_info WHERE (name = ? and user_id = ?) or id = ?) as cert_exists"));
    assert!(sql.contains("WHERE user_id = ?"));
    assert!(sql.contains("WHERE (SELECT cert_count FROM cert_checks) < ?"));
    assert!(sql.contains("AND (SELECT cert_exists FROM cert_checks) = false"));
}

#[test]
fn test_generate_add_cert_sql_postgres() {
    let db = MockDatabase::new(DatabaseBackend::Postgres).into_connection();
    let sql = CertRepository::generate_add_cert_sql(&db);

    // Verify PostgreSQL SQL statement
    assert!(!sql.contains("FROM dual")); // PostgreSQL doesn't need dual
    assert!(sql.contains("INSERT INTO t_cert_info"));
    assert!(sql.contains("WITH cert_checks AS"));
    assert!(sql.contains("COUNT(*) as cert_count"));
    assert!(sql.contains("EXISTS(SELECT 1 FROM t_cert_info WHERE (name = ? and user_id = ?) or id = ?) as cert_exists"));
    assert!(sql.contains("WHERE user_id = ?"));
    assert!(sql.contains("WHERE (SELECT cert_count FROM cert_checks) < ?"));
    assert!(sql.contains("AND (SELECT cert_exists FROM cert_checks) = false"));
}

#[test]
#[should_panic(expected = "Unsupported database backend")]
fn test_generate_add_cert_sql_when_unsupported_db_then_panic() {
    let db = MockDatabase::new(DatabaseBackend::Sqlite).into_connection();
    CertRepository::generate_add_cert_sql(&db);
}

#[test]
fn test_generate_add_cert_sql_when_whitespace_then_success() {
    let db = MockDatabase::new(DatabaseBackend::Postgres).into_connection();
    let sql = CertRepository::generate_add_cert_sql(&db);

    // Verify SQL format
    assert!(!sql.contains("  ,")); // Should not have extra spaces before commas
    assert!(!sql.contains(",,"));  // Should not have consecutive commas
    assert!(!sql.contains("( )")); // Should not have empty parentheses
    assert!(!sql.contains("WHERE WHERE")); // Should not have duplicate keywords
}