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

use sea_orm::{ColumnTrait, Condition, ConnectionTrait, DbErr, EntityTrait, PaginatorTrait, QuerySelect, Select};
use sea_orm::{QueryFilter, QueryOrder};

pub struct RepoExt {}

impl RepoExt {
    pub async fn query_all<E, C>(
        conn: &impl ConnectionTrait,
        select_columns: Vec<C>,
        filter_condition: Condition,
        order_by: C,
    ) -> Result<Vec<E::Model>, DbErr>
    where
        E: EntityTrait,
        E::Model: Sync + Send + 'static,
        C: ColumnTrait + Clone,
    {
        Self::build_query::<E, C>(select_columns, filter_condition, order_by).all(conn).await
    }

    pub async fn query_with_pagination<E, C>(
        conn: &impl ConnectionTrait,
        page_num: u64,
        page_size: u64,
        select_columns: Vec<C>,
        filter_condition: Condition,
        order_by: C,
    ) -> Result<Vec<E::Model>, DbErr>
    where
        E: EntityTrait,
        E::Model: Sync + Send + 'static,
        C: ColumnTrait + Clone,
    {
        Self::build_query::<E, C>(select_columns, filter_condition, order_by)
            .paginate(conn, page_size)
            .fetch_page(page_num)
            .await
    }

    pub async fn count_pages_with_condition<E, C>(
        conn: &impl ConnectionTrait,
        page_size: u64,
        condition: Condition,
        order_by: C,
    ) -> Result<u64, DbErr>
    where
        E: EntityTrait,
        E::Model: Sync + Send + 'static,
        C: ColumnTrait + Clone,
    {
        Self::build_query::<E, C>(vec![], condition, order_by) // 关键转换步骤
            .paginate(conn, page_size)
            .num_pages()
            .await
    }

    fn build_query<E, C>(select_columns: Vec<C>, filter_condition: Condition, order_by: C) -> Select<E>
    where
        E: EntityTrait,
        C: ColumnTrait + Clone,
    {
        let mut query = E::find();

        if !select_columns.is_empty() {
            query = query.select_only().columns(select_columns);
        }

        query.filter(filter_condition).order_by_asc(order_by)
    }
}
