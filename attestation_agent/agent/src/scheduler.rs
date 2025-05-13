use agent_utils::AgentError;
use chrono::Local;
use chrono::Utc;
use log::{debug, error, info, warn};
use rand::Rng;
use std::future::Future;
use std::ops::RangeInclusive;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::select;
use tokio::sync::{mpsc, Mutex};
use tokio::time::sleep;

pub struct SchedulerBuilders {
    schedulers: Vec<SingleTaskScheduler>,
}

impl SchedulerBuilders {
    pub fn new() -> Self {
        Self { schedulers: Vec::new() }
    }

    pub fn add(&mut self, config: SchedulerConfig, task: BoxedTask) {
        let scheduler = SingleTaskScheduler::new(config, task);
        self.schedulers.push(scheduler);
    }

    pub async fn start_all(&self) -> Result<(), AgentError> {
        for scheduler in self.schedulers.iter() {
            scheduler.start().await?;
        }
        Ok(())
    }

    pub async fn stop_all(&self) {
        for scheduler in self.schedulers.iter() {
            scheduler.stop().await;
        }
    }
}

/// Main configuration for the task scheduler.
///
/// This struct holds all configuration parameters for the scheduler,
/// including task identity, execution mode, initial execution and retry settings.
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Task name (used for logging)
    pub name: String,
    /// Time interval in seconds for the task to run
    pub intervals: u64,
    /// Delay range before the first execution (min..=max)
    pub initial_delay_range: RangeInclusive<Duration>,
    /// Whether retry is enabled for failed executions
    pub retry_enabled: bool,
    /// Maximum number of retry attempts
    pub retry_max_attempts: usize,
    /// Delay range between retry attempts (min..=max)
    pub retry_delay_range: RangeInclusive<Duration>,
    /// Maximum queue size (must be at least 1)
    pub max_queue_size: usize,
    /// Whether enable scheduling based on intervals
    pub enabled: bool,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            name: "unnamed_task".to_string(),
            initial_delay_range: Duration::from_secs(0)..=Duration::from_secs(0), // Default no delay
            retry_enabled: false,
            retry_max_attempts: 1,
            retry_delay_range: Duration::from_secs(0)..=Duration::from_secs(0), // Default no delay
            max_queue_size: 3,                                                  // Default queue size limit of 3
            enabled: true,
            intervals: 0,
        }
    }
}

impl SchedulerConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the name of the task for identification in logs.
    ///
    /// # Arguments
    ///
    /// * `name` - Name to identify the task in logs and diagnostics
    ///
    /// # Returns
    ///
    /// Self for method chaining
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Sets the minimum delay before the first task execution.
    ///
    /// # Arguments
    ///
    /// * `delay` - Minimum time to wait before the first execution
    ///
    /// # Returns
    ///
    /// Self for method chaining
    pub fn initial_delay(mut self, delay: Duration) -> Self {
        self.initial_delay_range = delay..=delay;
        self
    }

    /// Enables or disables retry attempts for the first execution.
    ///
    /// # Arguments
    ///
    /// * `enabled` - Whether to retry if the first execution fails
    ///
    /// # Returns
    ///
    /// Self for method chaining
    pub fn retry_enabled(mut self, enabled: bool) -> Self {
        self.retry_enabled = enabled;
        self
    }

    /// Sets the maximum delay before the first execution.
    ///
    /// This defines the upper bound of the delay range, where the actual delay will be
    /// randomly chosen between min_delay and max_delay.
    ///
    /// # Arguments
    ///
    /// * `max_delay` - Maximum total delay before first execution
    ///
    /// # Returns
    ///
    /// Result containing Self for method chaining, or an error if the maximum delay is invalid
    pub fn initial_max_delay(mut self, max_delay: Duration) -> Result<Self, AgentError> {
        let min_delay = *self.initial_delay_range.start();

        if max_delay < min_delay {
            error!("initial max_delay ({:?}) is less than min_delay ({:?})", max_delay, min_delay);
            return Err(AgentError::ConfigError(format!(
                "initial max_delay ({:?}) must be greater than or equal to min_delay ({:?})",
                max_delay, min_delay
            )));
        }

        self.initial_delay_range = min_delay..=max_delay;
        Ok(self)
    }

    /// Sets the minimum delay between retry attempts.
    ///
    /// # Arguments
    ///
    /// * `delay` - Minimum time to wait between retry attempts
    ///
    /// # Returns
    ///
    /// Self for method chaining
    pub fn retry_delay(mut self, delay: Duration) -> Self {
        self.retry_delay_range = delay..=delay;
        self
    }

    /// Sets the maximum delay between retry attempts.
    ///
    /// This defines the upper bound of the retry delay range, where the actual delay will be
    /// randomly chosen between min_delay and max_delay.
    ///
    /// # Arguments
    ///
    /// * `max_delay` - Maximum total delay between retry attempts
    ///
    /// # Returns
    ///
    /// Result containing Self for method chaining, or an error if the maximum delay is invalid
    pub fn retry_max_delay(mut self, max_delay: Duration) -> Result<Self, AgentError> {
        if max_delay < *self.retry_delay_range.start() {
            error!("retry max_delay ({:?}) is less than min_delay ({:?})", max_delay, *self.retry_delay_range.start());
            return Err(AgentError::ConfigError(format!(
                "retry max_delay ({:?}) must be greater than or equal to min_delay ({:?})",
                max_delay,
                *self.retry_delay_range.start()
            )));
        }

        self.retry_delay_range = *self.retry_delay_range.start()..=max_delay;
        Ok(self)
    }

    /// Sets or updates the interval time of the instance.
    ///
    /// This method uses a fluent interface (method chaining) to allow setting the interval time
    /// when creating or configuring an instance. It is mainly used to configure the instance
    /// to perform certain operations at specified time intervals.
    ///
    /// # Arguments
    /// - `time`: A 64-bit unsigned integer representing the interval time. The unit is second.
    ///
    /// # Returns
    /// Returns the instance itself after configuration, allowing further method chaining.
    pub fn intervals(mut self, time: u64) -> Self {
        self.intervals = time;
        self
    }

    /// Set the maximum queue size for tasks
    ///
    /// # Arguments
    ///
    /// * `size` - Maximum queue size (must be greater than zero)
    ///
    /// # Returns
    ///
    /// Result containing Self for method chaining, or an error if size is invalid
    pub fn max_queue_size(mut self, size: usize) -> Result<Self, AgentError> {
        if size == 0 {
            return Err(AgentError::ConfigError("Maximum queue size cannot be zero, must be at least 1".to_string()));
        }

        self.max_queue_size = size;
        Ok(self)
    }

    /// Sets the maximum number of retry attempts for the first execution.
    ///
    /// # Arguments
    ///
    /// * `max` - Maximum number of retry attempts
    ///
    /// # Returns
    ///
    /// Self for method chaining
    pub fn max_retries(mut self, max: usize) -> Self {
        self.retry_max_attempts = max;
        self
    }

    /// Enables or disables scheduled task
    ///
    /// # Arguments
    ///
    /// * `enabled` - Whether to enable or disable scheduled task
    ///
    /// # Returns
    ///
    /// Self for method chaining
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

/// Represents the current state of the scheduler.
///
/// This simplified enum tracks the basic lifecycle states of the scheduler.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SchedulerState {
    /// Scheduler has been created but not started or has been stopped
    Idle,
    /// Scheduler is running (either in first execution or periodic execution)
    Running,
    /// Scheduler is in the process of stopping
    Stopping,
}

/// Task function type for internal representation
type BoxedTask = Box<dyn Fn() -> Pin<Box<dyn Future<Output = Result<(), AgentError>> + Send>> + Send + Sync>;

/// Result type for waiting operations
#[derive(Debug)]
enum WaitResult {
    /// Time to execute the task
    TimeToExecute,
    /// Stop command received
    StopRequested,
}

/// Single-task scheduler for periodic task execution.
///
/// This scheduler is designed to manage a single recurring task with
/// configurable initial execution behavior and flexible scheduling options.
/// It supports features like:
///
/// - Delayed first execution with optional random jitter
/// - Configurable retry policy for first execution
/// - Periodic execution with fixed intervals OR schedule-based execution
/// - Clean shutdown with proper resource cleanup
struct SingleTaskScheduler {
    /// Task configuration
    config: SchedulerConfig,
    /// The task function to execute
    task: Option<Arc<BoxedTask>>,
    /// Current scheduler state
    state: Arc<Mutex<SchedulerState>>,
    /// Command sender channel
    tx: mpsc::Sender<()>,
    /// Command receiver channel
    rx: Arc<Mutex<mpsc::Receiver<()>>>,
    /// Current number of tasks in queue
    queue_size: Arc<Mutex<usize>>,
}

impl SingleTaskScheduler {
    /// Creates a new SingleTaskScheduler with the provided configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The configuration for the scheduler
    ///
    /// # Returns
    ///
    /// A new SingleTaskScheduler instance
    fn new(config: SchedulerConfig, task: BoxedTask) -> Self {
        let (tx, rx) = mpsc::channel(3);

        Self {
            config,
            task: Some(Arc::new(task)),
            state: Arc::new(Mutex::new(SchedulerState::Idle)),
            tx,
            rx: Arc::new(Mutex::new(rx)),
            queue_size: Arc::new(Mutex::new(0)),
        }
    }

    /// Starts the scheduler to begin executing the task.
    ///
    /// The scheduler will first execute the task after the configured initial delay,
    /// with retry attempts if enabled. After the first successful execution,
    /// it will continue with periodic execution based on the configured cron schedule.
    ///
    /// # Returns
    ///
    /// Ok(()) if the scheduler started successfully, or an error if it couldn't start.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - No task has been set
    /// - The scheduler is already running
    async fn start(&self) -> Result<(), AgentError> {
        self.validate_scheduler().await?;

        let mut state = self.state.lock().await;
        *state = SchedulerState::Running;
        drop(state);

        let task = Arc::clone(self.task.as_ref().unwrap());
        let config = self.config.clone();
        let state = Arc::clone(&self.state);
        let rx = Arc::clone(&self.rx);
        let queue_size = Arc::clone(&self.queue_size);

        tokio::spawn(async move {
            let first_execution_success = Self::handle_first_execution(&task, &config, &state, &rx).await;

            if let Err(e) = first_execution_success {
                warn!("The {} first execution failed, details: [{}]", config.name, e);
                *state.lock().await = SchedulerState::Idle;
                return;
            }

            if config.enabled {
                Self::handle_cron_execution(task, config, state, rx, queue_size).await;
            } else {
                Self::finish_execution(&state, &config.name).await;
                info!("The {} task is not scheduled to run periodically", config.name);
            }
        });

        Ok(())
    }

    async fn validate_scheduler(&self) -> Result<(), AgentError> {
        if self.task.is_none() {
            return Err(AgentError::ConfigError("No task set".to_string()));
        }

        let state = self.state.lock().await;
        if *state != SchedulerState::Idle {
            return Err(AgentError::ExecutionError(format!("Scheduler is already in state: {:?}", *state)));
        }

        Ok(())
    }

    fn calculate_delay(delay_range: &RangeInclusive<Duration>) -> Duration {
        let start = delay_range.start().as_millis() as u64;
        let end = delay_range.end().as_millis() as u64;

        if start >= end {
            return *delay_range.start();
        }

        let random_millis = rand::thread_rng().gen_range(start..=end);
        Duration::from_millis(random_millis)
    }

    async fn handle_first_execution(
        task: &Arc<BoxedTask>,
        config: &SchedulerConfig,
        state: &Arc<Mutex<SchedulerState>>,
        rx: &Arc<Mutex<mpsc::Receiver<()>>>,
    ) -> Result<(), AgentError> {
        let total_delay = Self::calculate_delay(&config.initial_delay_range);

        if total_delay.as_nanos() > 0 {
            info!(
                "Delaying first execution of task '{}' for {:?} (range: {:?} to {:?})",
                config.name,
                total_delay,
                config.initial_delay_range.start(),
                config.initial_delay_range.end()
            );
            let mut rx_guard = rx.lock().await;
            tokio::select! {
                _ = sleep(total_delay) => {
                },
                _ = rx_guard.recv() => {
                    info!("First execution of task '{}' canceled during initial delay", config.name);
                    return Err(AgentError::ExecutionError("First execution canceled".to_string()));
                }
            }
        }

        if *state.lock().await != SchedulerState::Running {
            return Err(AgentError::ExecutionError("Scheduler is not running".to_string()));
        }

        info!("Executing first run of task: {}", config.name);
        let result = Self::execute_task(&task).await;

        match result {
            Ok(_) => {
                info!("First execution completed successfully: {}", config.name);
                Ok(())
            },
            Err(e) => {
                error!("First execution failed: {} - {}", config.name, e);

                if !config.retry_enabled {
                    info!("Retry not enabled for first execution of task: {}", config.name);
                    return Err(AgentError::ExecutionError("Retry not enabled".to_string()));
                }

                return Self::handle_first_execution_retry(task, config, state, &rx).await;
            },
        }
    }

    async fn handle_first_execution_retry(
        task: &Arc<BoxedTask>,
        config: &SchedulerConfig,
        state: &Arc<Mutex<SchedulerState>>,
        rx: &Arc<Mutex<mpsc::Receiver<()>>>,
    ) -> Result<(), AgentError> {
        let retry_config = &config.retry_delay_range;
        let mut attempts = 0;

        while attempts < config.retry_max_attempts {
            let total_delay = Self::calculate_delay(&retry_config);

            debug!(
                "Waiting {:?} before retrying first execution of task: {} (range: {:?} to {:?})",
                total_delay,
                config.name,
                retry_config.start(),
                retry_config.end()
            );

            let mut rx_guard = rx.lock().await;
            tokio::select! {
                _ = sleep(total_delay) => {
                },
                _ = rx_guard.recv() => {
                    info!("First execution of task '{}' canceled during initial delay", config.name);
                    return Err(AgentError::ExecutionError("First execution canceled when retrying".to_string()));
                }
            }

            if *state.lock().await != SchedulerState::Running {
                return Err(AgentError::ExecutionError("Scheduler is not running".to_string()));
            }

            attempts += 1;
            debug!(
                "Retrying first execution of task: {} (attempt {}/{})",
                config.name, attempts, config.retry_max_attempts
            );

            let result = Self::execute_task(task).await;

            match result {
                Ok(_) => {
                    debug!("Retry succeeded for first execution of task: {}", config.name);
                    return Ok(());
                },
                Err(e) => {
                    error!("Retry attempt {} failed for first execution: {} - {}", attempts, config.name, e);
                },
            }
        }

        warn!("All retry attempts exhausted for first execution of task: {}", config.name);
        Err(AgentError::ExecutionError("All retry attempts exhausted".to_string()))
    }

    async fn handle_cron_execution(
        task: Arc<BoxedTask>,
        config: SchedulerConfig,
        state: Arc<Mutex<SchedulerState>>,
        rx: Arc<Mutex<mpsc::Receiver<()>>>,
        queue_size: Arc<Mutex<usize>>,
    ) {
        info!("Starting scheduled execution of task '{}' with intervals '{}' seconds", config.name, config.intervals);

        while !Self::should_stop(&state).await {
            match Self::wait_and_execute(&task, &config, &rx, &queue_size).await {
                Ok(true) => break,     // Stop the scheduler
                Ok(false) => continue, // Continue the loop
                Err(e) => {
                    error!("Error during task execution: {}", e);
                    break;
                },
            }
        }

        Self::finish_execution(&state, &config.name).await;
    }

    async fn should_stop(state: &Arc<Mutex<SchedulerState>>) -> bool {
        *state.lock().await == SchedulerState::Stopping
    }

    async fn finish_execution(state: &Arc<Mutex<SchedulerState>>, task_name: &str) {
        *state.lock().await = SchedulerState::Idle;
        info!("Scheduled execution stopped for task: {}", task_name);
    }

    async fn wait_and_execute(
        task: &Arc<BoxedTask>,
        config: &SchedulerConfig,
        rx: &Arc<Mutex<mpsc::Receiver<()>>>,
        queue_size: &Arc<Mutex<usize>>,
    ) -> Result<bool, AgentError> {
        match Self::wait_for_next_execution(config, rx).await {
            Ok(wait_result) => match wait_result {
                WaitResult::TimeToExecute => {
                    let should_stop = Self::process_task_execution(task, config, queue_size).await;
                    Ok(should_stop)
                },
                WaitResult::StopRequested => {
                    info!("Received stop command for task: {}", config.name);
                    Ok(true)
                },
            },
            Err(e) => {
                error!("Scheduling error for task '{}': {}", config.name, e);
                Ok(true)
            },
        }
    }

    async fn wait_for_next_execution(
        config: &SchedulerConfig,
        rx: &Arc<Mutex<mpsc::Receiver<()>>>,
    ) -> Result<WaitResult, AgentError> {
        let interval = Duration::from_secs(config.intervals);
        let next = Utc::now() + interval;
        info!("The next trigger time for the scheduled task is: {}", next.with_timezone(&Local));
        Self::wait_with_cancellation(interval, rx).await
    }

    async fn wait_with_cancellation(
        wait_duration: Duration,
        rx: &Arc<Mutex<mpsc::Receiver<()>>>,
    ) -> Result<WaitResult, AgentError> {
        let sleep_future = sleep(wait_duration);
        let mut rx_guard = rx.lock().await;

        select! {
            _ = sleep_future => Ok(WaitResult::TimeToExecute),
            cmd = rx_guard.recv() => match cmd {
                Some(_) => Ok(WaitResult::StopRequested),
                None => {
                    error!("Command channel closed unexpectedly, all senders have been dropped");
                    Err(AgentError::ExecutionError("Command channel closed unexpectedly".to_string()))
                }
            }
        }
    }

    async fn process_task_execution(
        task: &Arc<BoxedTask>,
        config: &SchedulerConfig,
        queue_size: &Arc<Mutex<usize>>,
    ) -> bool {
        let now = Utc::now();

        let should_execute = {
            let mut queue = queue_size.lock().await;
            if *queue < config.max_queue_size {
                *queue += 1;
                debug!("Adding task to queue for '{}' (new queue size: {})", config.name, *queue);
                true
            } else {
                info!("Queue full for task '{}' (size: {}), skipping execution at {}", config.name, *queue, now);
                false
            }
        };

        if !should_execute {
            return false;
        }

        info!("Executing scheduled task: {} at {}", config.name, now);

        let result = Self::execute_task(task).await;

        {
            let mut queue = queue_size.lock().await;
            *queue = queue.saturating_sub(1);
            debug!("Task completed for '{}' (queue size: {})", config.name, *queue);
        }

        match result {
            Ok(_) => {
                info!("Task completed successfully: {}", config.name);
                false
            },
            Err(e) => {
                error!("Task execution failed: {} - {}", config.name, e);
                false
            },
        }
    }

    async fn execute_task(task: &Arc<BoxedTask>) -> Result<(), AgentError> {
        let future = task();
        future.await
    }

    /// Stops the scheduler and any running tasks.
    ///
    /// This method sends a stop command to the scheduler and waits for it
    /// to actually stop before returning. The current task execution, if any,
    /// will be allowed to complete before the scheduler fully stops.
    ///
    /// # Example
    ///
    /// ```
    /// println!("Stopping scheduler...");
    /// scheduler.stop().await;
    /// println!("Scheduler stopped");
    /// ```
    async fn stop(&self) {
        let mut state = self.state.lock().await;
        if *state != SchedulerState::Running {
            return;
        }

        *state = SchedulerState::Stopping;
        drop(state);

        if let Err(e) = self.tx.send(()).await {
            debug!("Failed to send stop command: {}", e);
        }

        loop {
            let state = self.state.lock().await;
            if *state == SchedulerState::Idle {
                break;
            }
            drop(state);
            sleep(Duration::from_millis(10)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use chrono::Timelike;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn create_scheduler<F, Fut>(config: SchedulerConfig, task: F) -> SingleTaskScheduler
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), AgentError>> + Send + 'static,
    {
        let boxed_task: BoxedTask = Box::new(move || Box::pin(task()));
        SingleTaskScheduler::new(config, boxed_task)
    }

    #[tokio::test]
    async fn test_basic_execution() {
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = Arc::clone(&counter);

        let config = SchedulerConfig::new().name("test_task".to_string()).cron("*/1 * * * * *").unwrap();

        let scheduler = create_scheduler(config, move || {
            let counter = Arc::clone(&counter_clone);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        });

        // Start the scheduler, which triggers an immediate initial execution
        scheduler.start().await.unwrap();

        tokio::time::sleep(Duration::from_millis(4100)).await;
        scheduler.stop().await;

        let final_count = counter.load(Ordering::SeqCst);
        info!("Total task executions: {} (1 immediate + {} scheduled)", final_count, final_count - 1);

        // Consider the initial execution (1 time) plus the scheduled execution (5 times)
        assert!(
            final_count >= 4 && final_count <= 5,
            "Task should have executed 4-5 times, but got {} executions",
            final_count
        );
    }

    #[tokio::test]
    async fn test_default_scheduler_config() {
        let config = SchedulerConfig::default();
        assert_eq!(config.name, "unnamed_task");
        assert_eq!(config.intervals, 0);
        assert_eq!(*config.initial_delay_range.start(), Duration::from_secs(0));
        assert_eq!(*config.initial_delay_range.end(), Duration::from_secs(0));
        assert!(!config.retry_enabled);
        assert_eq!(config.retry_max_attempts, 1);
        assert_eq!(*config.retry_delay_range.start(), Duration::from_secs(0));
        assert_eq!(*config.retry_delay_range.end(), Duration::from_secs(0));
        assert_eq!(config.max_queue_size, 3);
        asserq_eq!(config.enabled, true);
    }

    #[tokio::test]
    async fn test_builder_methods() {
        let config = SchedulerConfig::new()
            .name("test_builder".to_string())
            .initial_delay(Duration::from_secs(2))
            .initial_max_delay(Duration::from_secs(5))
            .unwrap()
            .retry_enabled(true)
            .retry_delay(Duration::from_secs(1))
            .retry_max_delay(Duration::from_secs(3))
            .unwrap()
            .max_retries(3)
            .max_queue_size(5)
            .unwrap()
            .intervals(10)
            .enabled(false);

        let scheduler = create_scheduler(config.clone(), || async { Ok(()) });

        assert_eq!(scheduler.config.name, "test_builder");
        assert_eq!(scheduler.config.intervals, 10);
        assert_eq!(*scheduler.config.initial_delay_range.start(), Duration::from_secs(2));
        assert_eq!(*scheduler.config.initial_delay_range.end(), Duration::from_secs(5));
        assert!(scheduler.config.retry_enabled);
        assert_eq!(scheduler.config.retry_max_attempts, 3);
        assert_eq!(*scheduler.config.retry_delay_range.start(), Duration::from_secs(1));
        assert_eq!(*scheduler.config.retry_delay_range.end(), Duration::from_secs(3));
        assert_eq!(scheduler.config.max_queue_size, 5);
        asserq_eq!(scheduler.config.enabled, false);
    }

    #[tokio::test]
    async fn test_invalid_retry_delay() {
        let config = SchedulerConfig::new().retry_delay(Duration::from_secs(5));

        let result = config.retry_max_delay(Duration::from_secs(3));
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invalid_queue_size() {
        let result = SchedulerConfig::new().max_queue_size(0);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_start_without_task() {
        let config = SchedulerConfig::new();
        let mut scheduler = create_scheduler(config, || async { Ok(()) });
        scheduler.task = None;
        let result = scheduler.start().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_stop_when_idle() {
        let scheduler = create_scheduler(SchedulerConfig::new(), || async { Ok(()) });
        scheduler.stop().await;
    }

    #[tokio::test]
    async fn test_calculate_delay() {
        // Fixed delay
        let fixed_range = Duration::from_secs(5)..=Duration::from_secs(5);
        let delay = SingleTaskScheduler::calculate_delay(&fixed_range);
        assert_eq!(delay, Duration::from_secs(5));

        // Random delay range
        let random_range = Duration::from_secs(1)..=Duration::from_secs(10);
        let delay = SingleTaskScheduler::calculate_delay(&random_range);
        assert!(delay >= Duration::from_secs(1));
        assert!(delay <= Duration::from_secs(10));
    }

    #[tokio::test]
    async fn test_first_execution_failure_with_retry() {
        let execution_count = Arc::new(AtomicU32::new(0));
        let failure_count = Arc::new(AtomicU32::new(0));
        let execution_count_clone = Arc::clone(&execution_count);
        let failure_count_clone = Arc::clone(&failure_count);

        let success_flag = Arc::new(AtomicBool::new(false));
        let success_flag_clone = Arc::clone(&success_flag);

        let config = SchedulerConfig::new()
            .name("retry_test".to_string())
            .cron("*/5 * * * * *")
            .unwrap()
            .retry_enabled(true)
            .retry_delay(Duration::from_millis(100))
            .max_retries(2);

        let scheduler = create_scheduler(config, move || {
            let exec_count = Arc::clone(&execution_count_clone);
            let fail_count = Arc::clone(&failure_count_clone);
            let success = Arc::clone(&success_flag_clone);

            async move {
                let count = exec_count.fetch_add(1, Ordering::SeqCst);

                // First two executions fail
                if count < 2 {
                    fail_count.fetch_add(1, Ordering::SeqCst);
                    return Err(AgentError::ExecutionError("Simulated failure".to_string()));
                }

                // Third execution succeeds and sets flag
                success.store(true, Ordering::SeqCst);
                Ok(())
            }
        });

        scheduler.start().await.unwrap();

        let start_time = Utc::now();
        let timeout = Duration::from_millis(800);

        while !success_flag.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(50)).await;

            if (Utc::now() - start_time).to_std().unwrap() > timeout {
                break;
            }
        }

        scheduler.stop().await;

        assert!(success_flag.load(Ordering::SeqCst), "Task should have succeeded");
        assert_eq!(failure_count.load(Ordering::SeqCst), 2, "Should have 2 failures");

        let exec_count = execution_count.load(Ordering::SeqCst);
        assert!(exec_count >= 3, "Task should have executed at least 3 times (initial + 2 retries)");
    }

    #[tokio::test]
    async fn test_first_execution_all_retries_exhausted() {
        let execution_count = Arc::new(AtomicU32::new(0));
        let execution_count_clone = Arc::clone(&execution_count);

        let config = SchedulerConfig::new()
            .name("exhausted_retry_test".to_string())
            .cron("*/1 * * * * *")
            .unwrap()
            .retry_enabled(true)
            .retry_delay(Duration::from_millis(50))
            .max_retries(2);

        let scheduler = create_scheduler(config, move || {
            let counter = Arc::clone(&execution_count_clone);

            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                // Always fails
                Err(AgentError::ExecutionError("Simulated permanent failure".to_string()))
            }
        });

        scheduler.start().await.unwrap();

        tokio::time::sleep(Duration::from_millis(300)).await;

        assert_eq!(execution_count.load(Ordering::SeqCst), 3); // Initial + 2 retries
    }

    #[tokio::test]
    async fn test_cancel_during_execution() {
        let started = Arc::new(AtomicU32::new(0));
        let completed = Arc::new(AtomicU32::new(0));
        let started_clone = Arc::clone(&started);
        let completed_clone = Arc::clone(&completed);

        let config = SchedulerConfig::new().name("cancel_test".to_string()).cron("*/1 * * * * *").unwrap();

        let scheduler = create_scheduler(config, move || {
            let started_counter = Arc::clone(&started_clone);
            let completed_counter = Arc::clone(&completed_clone);

            async move {
                started_counter.fetch_add(1, Ordering::SeqCst);

                // Long-running task
                tokio::time::sleep(Duration::from_secs(2)).await;

                completed_counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        });

        scheduler.start().await.unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;

        scheduler.stop().await;

        assert!(started.load(Ordering::SeqCst) >= 1, "Task should have started");

        if started.load(Ordering::SeqCst) > 1 {
            assert!(
                completed.load(Ordering::SeqCst) < started.load(Ordering::SeqCst),
                "Some tasks should have been interrupted"
            );
        }
    }

    #[tokio::test]
    async fn test_initial_max_delay_validation() {
        // Test when max delay is less than min delay
        let config1 = SchedulerConfig::new().initial_delay(Duration::from_secs(10));

        let result = config1.initial_max_delay(Duration::from_secs(5));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("initial max_delay"));
    }

    #[tokio::test]
    async fn test_start_error_conditions() {
        // 1. Test starting without a task
        let scheduler_no_task = SingleTaskScheduler {
            config: SchedulerConfig::new().cron("* * * * * *").unwrap(),
            task: None,
            state: Arc::new(Mutex::new(SchedulerState::Idle)),
            tx: mpsc::channel(3).0,
            rx: Arc::new(Mutex::new(mpsc::channel(3).1)),
            queue_size: Arc::new(Mutex::new(0)),
        };

        let result = scheduler_no_task.start().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No task set"));

        // 2. Test enabling retry without cron expression
        let config_no_cron = SchedulerConfig::new().retry_enabled(true);
        let scheduler_no_cron = create_scheduler(config_no_cron, || async { Ok(()) });

        let result = scheduler_no_cron.start().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Cron expression must be set"));

        // 4. Test if scheduler is already in running state
        let running_config = SchedulerConfig::new().cron("* * * * * *").unwrap();
        let scheduler_running = create_scheduler(running_config, || async { Ok(()) });

        // Start once
        let _ = scheduler_running.start().await;

        // Restart should fail
        let result = scheduler_running.start().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already in state"));

        // Stop the scheduler
        scheduler_running.stop().await;
    }

    #[tokio::test]
    async fn test_start_already_running_state() {
        let execution_count = Arc::new(AtomicU32::new(0));
        let execution_count_clone = Arc::clone(&execution_count);

        let config = SchedulerConfig::new().name("already_running_test".to_string()).cron("*/1 * * * * *").unwrap();

        let scheduler = create_scheduler(config, move || {
            let counter = Arc::clone(&execution_count_clone);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        });

        // First start should succeed
        let result = scheduler.start().await;
        assert!(result.is_ok(), "First start should succeed");

        // Second start while running should fail
        let result = scheduler.start().await;
        assert!(result.is_err(), "Second start while running should fail");
        assert!(
            result.unwrap_err().to_string().contains("already in state"),
            "Error should indicate scheduler is already running"
        );

        // Stop the scheduler
        scheduler.stop().await;

        // Start after stop should succeed
        let result = scheduler.start().await;
        assert!(result.is_ok(), "Start after stop should succeed");

        // Cleanup
        scheduler.stop().await;
    }

    #[tokio::test]
    async fn test_scheduler_builders() {
        // Create counters for each task
        let counter1 = Arc::new(AtomicU32::new(0));
        let counter2 = Arc::new(AtomicU32::new(0));
        let counter1_clone = Arc::clone(&counter1);
        let counter2_clone = Arc::clone(&counter2);

        // Create builder
        let mut builders = SchedulerBuilders::new();

        // Create first task
        let config1 = SchedulerConfig::new().name("task1".to_string()).cron("*/1 * * * * *").unwrap();

        let task1: BoxedTask = Box::new(move || {
            let counter = Arc::clone(&counter1_clone);
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        });

        // Create second task
        let config2 = SchedulerConfig::new().name("task2".to_string()).cron("*/1 * * * * *").unwrap();

        let task2: BoxedTask = Box::new(move || {
            let counter = Arc::clone(&counter2_clone);
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        });

        // Add tasks to builder
        builders.add(config1, task1);
        builders.add(config2, task2);

        // Start all schedulers
        builders.start_all().await.unwrap();

        // Wait for tasks to execute
        tokio::time::sleep(Duration::from_millis(1500)).await;

        // Stop all schedulers
        builders.stop_all().await;

        // Verify that both tasks executed
        assert!(counter1.load(Ordering::SeqCst) > 0, "First task should have executed");
        assert!(counter2.load(Ordering::SeqCst) > 0, "Second task should have executed");
    }

    #[tokio::test]
    async fn test_scheduler_builders_error_propagation() {
        // Create builder
        let mut builders = SchedulerBuilders::new();

        // Add a valid scheduler
        let config1 = SchedulerConfig::new().name("valid_task".to_string()).cron("*/1 * * * * *").unwrap();

        let task1: BoxedTask = Box::new(|| Box::pin(async { Ok(()) }));
        builders.add(config1, task1);

        // Add an invalid scheduler (missing cron expression)
        let config2 = SchedulerConfig::new().name("invalid_task".to_string());

        let task2: BoxedTask = Box::new(|| Box::pin(async { Ok(()) }));
        builders.add(config2, task2);

        // Starting all should fail due to the invalid scheduler
        let result = builders.start_all().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Cron expression must be set"));

        // No schedulers should be running
        builders.stop_all().await; // Should be safe even if nothing is running
    }
}
