use std::collections::HashMap;
use std::sync::Arc;
use std::thread;
use parking_lot::Mutex;
use super::task::Task;

/// Task Scheduler
pub struct Scheduler {
    /// Task mapping table, where key is the task ID
    tasks: HashMap<String, Arc<Task>>,
    /// Scheduler running status
    running: bool,
}

impl Scheduler {
    pub fn new() -> Self {
        Scheduler {
            tasks: HashMap::new(),
            running: false,
        }
    }

    /// Start the scheduler
    pub fn start(&mut self) {
        if self.running {
            return;
        }
        self.running = true;

        // Clone task list for sharing between threads
        let tasks = Arc::new(Mutex::new(self.tasks.clone()));

        // Start scheduler thread
        thread::spawn(move || {
            while Arc::strong_count(&tasks) > 1 {
                let task_map = tasks.lock();
                for (_, task) in task_map.iter() {
                    task.try_execute();
                }
                drop(task_map);
                thread::sleep(std::time::Duration::from_secs(1));
            }
        });
    }

    /// Add task
    pub fn add_task(&mut self, task: Task) -> Result<(), String> {
        if self.tasks.contains_key(&task.id) {
            return Err(format!("Task ID {} already exists", task.id));
        }
        self.tasks.insert(task.id.clone(), Arc::new(task));
        Ok(())
    }

    /// Delete task
    pub fn delete_task(&mut self, task_id: String) -> bool {
        self.tasks.remove(&task_id).is_some()
    }

    /// Update task
    pub fn update_task(
        &mut self,
        task_id: String,
        cron_expr: Option<String>,
        task_fn: Option<Arc<dyn Fn() + Send + Sync + 'static>>,
        exec_count: Option<u32>,
    ) -> Result<(), String> {
        let task = self.tasks.get(&task_id)
            .ok_or_else(|| format!("Task ID {} does not exist", task_id))?;

        let new_task = Task::new(
            task_id.clone(),
            cron_expr.unwrap_or_else(|| task.cron_expr.clone()),
            task_fn.unwrap_or_else(|| task.task_fn.clone()),
            exec_count.unwrap_or(task.exec_count),
        );

        self.tasks.insert(task_id, Arc::new(new_task));
        Ok(())
    }
}