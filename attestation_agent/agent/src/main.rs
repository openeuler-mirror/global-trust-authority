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

mod scheduler;

use crate::scheduler::SchedulerConfig;
use actix_web::{http::Method, HttpRequest};
use agent_restful::rest::{RestService, ServiceConfig};
use agent_restful::{get_evidence_controller, token_controller};
use agent_utils::load_plugins;
use agent_utils::{AgentError, Client, ClientConfig};
use challenge::do_challenge;
use challenge::AttesterInfo;
use config::{ConfigManager, InitialDelayConfig, AGENT_CONFIG};
use log::LevelFilter;
use log::{debug, error, info};
use log4rs::{
    append::file::FileAppender,
    config::{Appender, Config, Root},
    encode::pattern::PatternEncoder,
};
use scheduler::SchedulerBuilders;
use serde_json::Value;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::pin;
use tokio::time::Duration;
use std::fs;
use std::os::unix::fs::PermissionsExt;

const MAX_QUEUE_SIZE: usize = 3;

#[tokio::main]
async fn main() -> Result<(), AgentError> {
    info!("Remote Attestation Client starting");

    // Use command line arguments if provided
    let args: Vec<String> = std::env::args().collect();
    let config_path = if args.len() > 1 { &args[1] } else { "" };

    info!("Starting to load configuration file");
    let config_manager: Arc<ConfigManager> = Arc::new(
        ConfigManager::new(config_path)
            .map_err(|e| AgentError::ConfigError(format!("Failed to initialize ConfigManager: {}", e)))?,
    );

    info!("Configuration file loaded successfully: {}", config_manager.get_config_path());

    // Get configuration object
    let config: config::Config = AGENT_CONFIG
        .get_instance()
        .map_err(|e| AgentError::ConfigError(format!("Failed to get agent config instance: {}", e)))?
        .clone();

    let log_file = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new("{d(%Y-%m-%d %H:%M:%S:%3f)} {l} [{M}:{L}] - {m}{n}")))
        .build(&config.logging.file)
        .map_err(|e| AgentError::IoError(format!("Failed to build log file appender: {}", e)))?;

    // Set log file permissions to 640
    if let Err(e) = fs::set_permissions(&config.logging.file, PermissionsExt::from_mode(0o640)) {
        error!("Failed to set log file permissions: {}", e);
    }

    let log_level = match config.logging.level.to_lowercase().as_str() {
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        "off" => LevelFilter::Off,
        _ => LevelFilter::Info,
    };

    let log_config = Config::builder()
        .appender(Appender::builder().build("file", Box::new(log_file)))
        .build(Root::builder().appender("file").build(log_level))
        .map_err(|e| AgentError::ConfigError(format!("Failed to build log config: {}", e)))?;

    if let Err(e) = log4rs::init_config(log_config) {
        error!("Failed to initialize logger: {}", e);
        return Err(AgentError::IoError(format!("Failed to initialize logger: {}", e)));
    }

    // Print working directory and some basic information
    info!(
        "Current working directory: {:?}",
        std::env::current_dir().map_err(|e| AgentError::IoError(format!("Failed to get current directory: {}", e)))?
    );

    // Load plugins
    info!("Starting to load plugins");
    load_plugins(&config).map_err(|e| AgentError::PluginLoadError(format!("Failed to load plugins: {}", e)))?;
    info!("Plugins loaded successfully");

    // start server
    info!("Starting server at listen address: {}:{}", config.agent.listen_address, config.agent.listen_port);
    let rest_config =
        ServiceConfig::new().with_port(config.agent.listen_port).with_bind_address(&config.agent.listen_address);

    let service = RestService::configure(rest_config)?;

    service.register(
        Method::POST,
        "/global-trust-authority/agent/v1/tokens",
        |_: HttpRequest, body: Option<Value>| token_controller::get_token(body),
    )?;
    service.register(
        Method::POST,
        "/global-trust-authority/agent/v1/evidences",
        |_: HttpRequest, body: Option<Value>| get_evidence_controller::get_evidence(body),
    )?;

    service.start_server().await?;

    debug!("Server URL from config: {}", config.server.server_url);
    let mut client_config = ClientConfig::new().with_base_url(config.server.server_url.clone());

    // Configure TLS certificates
    if let Some(tls_config) = &config.server.tls {
        debug!("TLS configuration found, configuring certificates");
        client_config =
            client_config.with_certificates(&tls_config.cert_path, &tls_config.key_path, &tls_config.ca_path);
    }

    Client::configure(client_config)?;

    let challenge_config = match config.schedulers.iter().find(|config| config.name == "challenge".to_string()) {
        Some(config) => config,
        None => {
            log::error!("Challenge scheduler not found in configuration, skipping challenge initialization");
            if let Err(e) = service.stop_server().await {
                error!("Failed to stop server: {}", e);
            }
            return Err(AgentError::ConfigError("Challenge scheduler not configured".to_string()));
        },
    };

    let initial_delay =
        challenge_config.initial_delay.clone().unwrap_or_else(|| InitialDelayConfig { min_seconds: 0, max_seconds: 0 });
    let max_retries = challenge_config.max_retries.unwrap_or(1);
    // start scheduler
    let scheduler_config = SchedulerConfig::new()
        .name(challenge_config.name.clone())
        .intervals(challenge_config.intervals)
        .initial_delay(Duration::from_secs(initial_delay.min_seconds))
        .initial_max_delay(Duration::from_secs(initial_delay.max_seconds))
        .unwrap()
        .retry_delay(Duration::from_secs(initial_delay.min_seconds))
        .retry_max_delay(Duration::from_secs(initial_delay.max_seconds))
        .unwrap()
        .max_retries(max_retries)
        .max_queue_size(MAX_QUEUE_SIZE)
        .unwrap()
        .retry_enabled(challenge_config.retry_enabled)
        .enabled(challenge_config.enabled);

    let task = Box::new(move || {
        std::thread::spawn(|| {
            info!("Scheduler task executed (threaded)");
            let attester_info: Option<Vec<AttesterInfo>> = None;
            let attester_data: Option<String> = None;
            let result = {
                let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
                rt.block_on(async { do_challenge(&attester_info, &attester_data).await })
            };
            if let Err(e) = result {
                log::error!("do_challenge failed in scheduler thread: {}", e);
            }
        });
        Box::pin(async { Ok(()) }) as Pin<Box<dyn Future<Output = Result<(), agent_utils::AgentError>> + Send>>
    });

    let mut schedulers = SchedulerBuilders::new();
    schedulers.add(scheduler_config, task);

    match schedulers.start_all().await {
        Ok(_) => info!("Scheduler started successfully"),
        Err(e) => {
            let err_msg = format!("{}", e);
            error!("{}", err_msg);
            return Err(AgentError::SchedulerTaskError(err_msg));
        },
    }

    let mut term_signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| AgentError::IoError(format!("Failed to register TERM signal handler: {}", e)))?;

    let mut int_signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|e| AgentError::IoError(format!("Failed to register INT signal handler: {}", e)))?;

    let ctrl_c = tokio::signal::ctrl_c();

    pin!(ctrl_c);

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C signal");
        }
        _ = term_signal.recv() => {
            info!("Received SIGTERM signal");
        }
        _ = int_signal.recv() => {
            info!("Received SIGINT signal");
        }
    }

    schedulers.stop_all().await;

    service
        .stop_server()
        .await
        .map_err(|e| AgentError::ServerShutdownError(format!("Failed to stop server: {}", e)))?;

    Ok(())
}
