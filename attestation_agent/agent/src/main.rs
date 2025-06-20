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
use log::{debug, error, info};
use common_log::config::{LogConfig, LoggerConfig};
use common_log::init_with_config;
use scheduler::SchedulerBuilders;
use serde_json::Value;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::pin;
use tokio::time::Duration;
use std::path::Path;

const MAX_QUEUE_SIZE: usize = 3;
const MAX_LOG_FILE_SIZE: u64 = 10485760; // 10MB
const MAX_LOG_FILE_COUNT: u32 = 6;

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

    // init log config
    let log_path = Path::new(&config.logging.file);
    let log_directory = log_path.parent().and_then(|p| p.to_str()).unwrap_or("/var/log").to_string();
    let log_file_name = log_path.file_name().and_then(|name| name.to_str()).unwrap_or("ra-agent.log").to_string();

    let log_config = LogConfig {
        loggers: vec![LoggerConfig {
            path_prefix: "root".to_string(),
            log_directory,
            log_file_name,
            max_file_size: MAX_LOG_FILE_SIZE,
            max_zip_count: MAX_LOG_FILE_COUNT,
            level: config.logging.level.clone(),
        }]
    };

    init_with_config(log_config)
        .map_err(|e| AgentError::IoError(format!("Failed to initialize logger: {}", e)))?;
    info!("Logger initialized");

    // Print working directory and some basic information
    info!(
        "Current working directory: {:?}",
        std::env::current_dir().map_err(|e| AgentError::IoError(format!("Failed to get current directory: {}", e)))?
    );

    // Load plugins
    info!("Starting to load plugins");
    load_plugins(&config).map_err(|e| AgentError::PluginLoadError(format!("Failed to load plugins: {}", e)))?;
    info!("Plugins loaded successfully");

    let challenge_config =
    if let Some(config) = config.schedulers.iter().find(|config| config.name == "challenge") {
        config
    } else {
        error!("Challenge scheduler not found in configuration");
        return Err(AgentError::ConfigError("Challenge scheduler not configured".to_string()));
    };

    // start server
    let service: Option<Arc<RestService>> = if config.agent.listen_enabled {
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
        Some(service)
    } else {
        info!("agent restful service is disabled");
        None
    };

    debug!("Server URL from config: {}", config.server.server_url);
    let mut client_config = ClientConfig::new().with_base_url(config.server.server_url.clone());

    // Configure TLS certificates
    if let Some(tls_config) = &config.server.tls {
        debug!("TLS configuration found, configuring certificates");
        client_config =
            client_config.with_certificates(&tls_config.cert_path, &tls_config.key_path, &tls_config.ca_path);
    }

    Client::configure(client_config)?;

    let initial_delay =
        challenge_config.initial_delay.clone().unwrap_or(InitialDelayConfig { min_seconds: 0, max_seconds: 0 });
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
            let attester_data: Option<serde_json::Value> = None;
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

    if let Some(service) = service {
        service
            .stop_server()
            .await
            .map_err(|e| AgentError::ServerShutdownError(format!("Failed to stop server: {}", e)))?;
        info!("Server stopped successfully");
    }

    Ok(())
}
