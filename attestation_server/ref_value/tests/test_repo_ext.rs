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

use sea_orm::entity::prelude::*;
use sea_orm::{ColumnTrait, Condition, ConnectionTrait, DatabaseBackend, EntityTrait, MockDatabase};
use rv::repositories::repo_ext::RepoExt;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "test")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub name: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

#[tokio::test]
async fn test_query_all_success() {
    // test_data
    let test_data = vec![
        Model {
            id: 1,
            name: "test1".to_string(),
        },
        Model {
            id: 2,
            name: "test2".to_string(),
        },
    ];

    // db mock
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![test_data.clone()])
        .into_connection();

    let select_columns = vec![Column::Id, Column::Name];
    let filter_condition = Condition::all().add(Column::Id.gt(0));
    let order_by = Column::Id;

    let result = RepoExt::query_all::<Entity, Column>(
        &db,
        select_columns,
        filter_condition,
        order_by,
    )
        .await;

    assert!(result.is_ok());
    let models = result.unwrap();
    assert_eq!(models.len(), 2);
    assert_eq!(models, test_data);
}

#[tokio::test]
async fn test_query_all_db_error() {
    //  db mock
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors(vec![DbErr::Custom("Database error".to_string())])
        .into_connection();

    let select_columns = vec![Column::Id, Column::Name];
    let filter_condition = Condition::all().add(Column::Id.gt(0));
    let order_by = Column::Id;

    let result = RepoExt::query_all::<Entity, Column>(
        &db,
        select_columns,
        filter_condition,
        order_by,
    )
        .await;

    assert!(result.is_err());
    match result {
        Err(DbErr::Custom(msg)) => assert_eq!(msg, "Database error"),
        _ => panic!("Expected Custom DbErr"),
    }
}

#[tokio::test]
async fn test_query_with_pagination_success() {
    let test_data = vec![
        Model {
            id: 1,
            name: "test1".to_string(),
        },
        Model {
            id: 2,
            name: "test2".to_string(),
        },
    ];

    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_results(vec![test_data.clone()])
        .into_connection();

    let select_columns = vec![Column::Id, Column::Name];
    let filter_condition = Condition::all().add(Column::Id.gt(0));
    let order_by = Column::Id;

    let result = RepoExt::query_with_pagination::<Entity, Column>(
        &db,
        0,
        10,
        select_columns,
        filter_condition,
        order_by,
    )
        .await;

    assert!(result.is_ok());
    let models = result.unwrap();
    assert_eq!(models.len(), 2);
    assert_eq!(models, test_data);
}

#[tokio::test]
async fn test_count_pages_db_error() {
    let db = MockDatabase::new(DatabaseBackend::Postgres)
        .append_query_errors(vec![DbErr::Custom("Database error".to_string())])
        .into_connection();

    let condition = Condition::all().add(Column::Id.gt(0));
    let order_by = Column::Id;

    let result = RepoExt::count_pages_with_condition::<Entity, Column>(
        &db,
        10,
        condition,
        order_by,
    )
        .await;

    assert!(result.is_err());
    match result {
        Err(DbErr::Custom(msg)) => assert_eq!(msg, "Database error"),
        _ => panic!("Expected Custom DbErr"),
    }
}