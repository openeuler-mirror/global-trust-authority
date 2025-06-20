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

use std::sync::Arc;
use std::time::SystemTime;
use cron::Schedule;
use parking_lot::Mutex;
use std::str::FromStr;

/// Scheduled Task
pub struct Task {
    /// Task ID
    pub id: String,
    /// Cron expression
    pub cron_expr: String,
    /// Task scheduler
    schedule: Schedule,
    /// Task function
    pub task_fn: Arc<dyn Fn() + Send + Sync + 'static>,
    /// Last execution time
    last_run: Arc<Mutex<Option<SystemTime>>>,
    /// Execution count limit, 0 means unlimited
    pub exec_count: u32,
    /// Current execution count
    executed_count: Arc<Mutex<u32>>,
}

impl Task {
    /// Create a new task
    /// 
    /// # Arguments
    /// 
    /// * `id` - Task ID
    /// * `cron_expr` - Cron expression
    /// * `task_fn` - Task function
    /// * `exec_count` - Execution count limit
    /// 
    /// # Returns
    /// 
    /// * `Self` - New task
    pub fn new(
        id: String,
        cron_expr: String,
        task_fn: Arc<dyn Fn() + Send + Sync + 'static>,
        exec_count: u32,
    ) -> Self {
        let schedule = Schedule::from_str(&cron_expr)
            .expect("nvalid cron expression");
        
        Task {
            id,
            cron_expr,
            schedule,
            task_fn,
            last_run: Arc::new(Mutex::new(None)),
            exec_count,
            executed_count: Arc::new(Mutex::new(0)),
        }
    }

    /// Try to execute the task
    pub fn try_execute(&self) {
        let now = SystemTime::now();
        let mut last_run = self.last_run.lock();
        let mut executed_count = self.executed_count.lock();

        // Check execution count limit
        if self.exec_count > 0 && *executed_count >= self.exec_count {
            return;
        }

        // Check if next execution time has been reached
        if let Some(last) = *last_run {
            if !self.should_run(last, now) {
                return;
            }
        }

        // Execute the task
        (self.task_fn)();
        *last_run = Some(now);
        *executed_count += 1;
    }

    /// Check if the task should be executed
    /// 
    /// # Arguments
    /// 
    /// * `last` - Last execution time
    /// * `now` - Current time
    /// 
    /// # Returns
    /// 
    /// * `bool` - True if the task should be executed, false otherwise    
    fn should_run(&self, last: SystemTime, now: SystemTime) -> bool {
        // Convert SystemTime to DateTime
        let last_dt: chrono::DateTime<chrono::Local> = chrono::DateTime::from(last);
        let now_dt: chrono::DateTime<chrono::Local> = chrono::DateTime::from(now);

        // Get the next scheduled execution time after the last execution
        if let Some(next) = self.schedule.after(&last_dt).take(1).next() {
            // Check if the next scheduled execution time is before or equal to current time
            // And ensure the difference with current time is within a small threshold (e.g. 1 second)
            next <= now_dt && (now_dt - next).num_seconds() < 1
        } else {
            false
        }
    }
}