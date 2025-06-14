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

use crate::agent_error::AgentError;
use crate::validate::validate_utils::validate_file;
use config::AGENT_CONFIG;
use log::{debug, error, info};
use once_cell::sync::OnceCell;
use reqwest::{Client as ReqwestClient, Method, Proxy, Response};
use serde_json::Value;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use validator::Validate;

const CLIENT_CONNECTION_TIMEOUT: u64 = 60; // Client connection timeout in seconds

// Certificate configuration struct
#[derive(Validate)]
#[derive(Clone, Debug)]
pub struct CertConfig {
    #[validate(custom(function = "validate_file"))]
    cert_path: String,
    #[validate(custom(function = "validate_file"))]
    key_path: String,
    #[validate(custom(function = "validate_file"))]
    ca_path: String,
}

// Client configuration struct, containing base configuration and optional certificate configuration
#[derive(Clone, Debug, Validate, Default)]
pub struct ClientConfig {
    #[validate(url)]
    base_url: String,
    #[validate(url)]
    proxy: Option<String>,
    cert_config: Option<CertConfig>,
}

impl ClientConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_base_url(mut self, base_url: String) -> Self {
        self.base_url = base_url;
        self
    }

    pub fn with_proxy(mut self, proxy: Option<String>) -> Self {
        self.proxy = proxy;
        self
    }

    pub fn with_certificates(mut self, cert_path: &str, key_path: &str, ca_path: &str) -> Self {
        self.cert_config = Some(CertConfig {
            cert_path: cert_path.to_string(),
            key_path: key_path.to_string(),
            ca_path: ca_path.to_string(),
        });
        self
    }

    /// Validates the client configuration.
    ///
    /// This method performs comprehensive validation of the client configuration, including:
    /// - Basic configuration validation (using the Validate trait)
    /// - HTTPS-specific validation:
    ///   - Checks if `base_url` starts with "https://"
    ///   - If HTTPS is used, validates that certificate configuration is present
    ///   - Validates the certificate configuration if present
    ///
    /// # Returns
    ///
    /// * `Result<(), AgentError>` - Returns `Ok(())` if all validations pass,
    ///   otherwise returns an `AgentError` with a descriptive error message.
    ///
    /// # Errors
    ///
    /// Returns an `AgentError::ConfigError` in the following cases:
    /// * Basic configuration validation fails
    /// * HTTPS is used but certificate configuration is missing
    /// * Certificate configuration validation fails
    ///
    /// # Examples
    ///
    /// ```rust
    /// // HTTP configuration
    /// let config = ClientConfig {
    ///     base_url: "http://example.com".to_string(),
    ///     cert_config: None,
    ///     ..Default::default()
    /// };
    /// assert!(config.validate_config().is_ok());
    ///
    /// // HTTPS configuration with certificates
    /// let config = ClientConfig {
    ///     base_url: "https://example.com".to_string(),
    ///     cert_config: Some(CertConfig {
    ///         cert_path: Some("cert.pem".to_string()),
    ///         key_path: Some("key.pem".to_string()),
    ///         ca_path: Some("ca.pem".to_string()),
    ///     }),
    ///     ..Default::default()
    /// };
    /// assert!(config.validate_config().is_ok());
    /// ```
    pub fn validate_config(&self) -> Result<(), AgentError> {
        if let Err(err) = self.validate() {
            return Err(AgentError::ConfigError(format!("Validation failed: {:?}", err)));
        }

        // If base_url starts with https, certificate configuration is required
        if self.base_url.starts_with("https://") {
            if let Some(cert_config) = &self.cert_config {
                if let Err(err) = cert_config.validate() {
                    return Err(AgentError::ConfigError(format!("Certificate validation failed: {:?}", err)));
                }
            } else {
                return Err(AgentError::ConfigError("Certificate configuration is required for HTTPS".to_string()));
            }
        }

        Ok(())
    }
}

pub struct Client {
    config: RwLock<ClientConfig>,
    client: RwLock<Option<ReqwestClient>>,
}

static CLIENT_INSTANCE: OnceCell<Arc<Client>> = OnceCell::new();

impl Client {
    fn default() -> Self {
        Self { config: RwLock::new(ClientConfig::default()), client: RwLock::new(None) }
    }

    pub fn instance() -> Arc<Self> {
        CLIENT_INSTANCE.get_or_init(|| Arc::new(Self::default())).clone()
    }

    pub fn configure(config: ClientConfig) -> Result<Arc<Self>, AgentError> {
        let instance = Self::instance();
        if let Err(err) = config.validate_config() {
            error!("Configuration validation failed: {:?}", err);
            return Err(AgentError::ConfigError(format!("Invalid configuration: {:?}", err)));
        }

        // Update the configuration
        {
            let mut config_guard = instance.config.write().map_err(|e| {
                error!("Failed to acquire config lock: {}", e);
                AgentError::LockError(format!("Cannot acquire config lock: {}", e))
            })?;
            *config_guard = config;
        }

        // Initialize HTTP client
        {
            let config = instance.get_config()?;
            debug!("Initializing HTTP client with base_url: {}", config.base_url);
            let client = Self::create_client(&config)?;
            let mut client_guard = instance.client.write().map_err(|e| {
                error!("Failed to acquire client lock: {}", e);
                AgentError::LockError(format!("Cannot acquire client lock: {}", e))
            })?;
            *client_guard = Some(client);
        }

        Ok(instance)
    }

    fn create_client(config: &ClientConfig) -> Result<ReqwestClient, AgentError> {
        let mut builder = ReqwestClient::builder().timeout(Duration::from_secs(CLIENT_CONNECTION_TIMEOUT));

        if config.base_url.starts_with("https://") {
            if let Some(cert_config) = &config.cert_config {
                // Read files
                let cert_data = std::fs::read(&cert_config.cert_path)
                    .map_err(|e| AgentError::SslError(format!("Failed to read certificate: {}", e)))?;
                let key_data = std::fs::read(&cert_config.key_path)
                    .map_err(|e| AgentError::SslError(format!("Failed to read private key: {}", e)))?;
                let ca_data = std::fs::read(&cert_config.ca_path)
                    .map_err(|e| AgentError::SslError(format!("Failed to read CA certificate: {}", e)))?;

                // Create Identity and Certificate
                let identity = reqwest::Identity::from_pkcs8_pem(&cert_data, &key_data)
                    .map_err(|e| AgentError::SslError(format!("Failed to create identity: {}", e)))?;
                let ca_cert = reqwest::Certificate::from_pem(&ca_data)
                    .map_err(|e| AgentError::SslError(format!("Failed to create CA certificate: {}", e)))?;

                // Build client configuration
                builder = builder
                    .identity(identity)
                    .add_root_certificate(ca_cert)
                    .danger_accept_invalid_certs(false)
                    .danger_accept_invalid_hostnames(false);
            }
        }

        // Handle other configurations such as proxy...
        if let Some(proxy_url) = config.proxy.as_deref() {
            let proxy = Proxy::all(proxy_url).map_err(|e| {
                error!("Invalid proxy URL: {}", e);
                AgentError::ConfigError(e.to_string())
            })?;
            builder = builder.proxy(proxy);
        }

        match builder.build() {
            Ok(client) => Ok(client),
            Err(e) => {
                error!("Failed to build HTTP client: {}", e);
                Err(AgentError::ConfigError(e.to_string()))
            },
        }
    }

    /// Helper function: masks sensitive information in proxy URLs
    fn mask_sensitive_info(url: &str) -> String {
        url.split('@').next_back().map_or_else(|| url.to_string(), |masked| format!("***@{}", masked))
    }

    /// Sends an HTTP request to the server with optional JSON payload.
    ///
    /// This method handles the complete request lifecycle including:
    /// - Acquiring the HTTP client lock
    /// - Constructing the request URL
    /// - Adding JSON payload if provided
    /// - Adding required headers (Content-Type and User-Id)
    /// - Sending the request and handling the response
    ///
    /// # Arguments
    ///
    /// * `method` - The HTTP method to use (GET, POST, etc.)
    /// * `path` - The API endpoint path to request
    /// * `json` - Optional JSON payload to send with the request
    ///
    /// # Returns
    ///
    /// * `Result<Response, AgentError>` - Returns the HTTP response if successful,
    ///   otherwise returns an appropriate `AgentError`
    ///
    /// # Errors
    ///
    /// Returns an `AgentError` in the following cases:
    /// * `LockError` - If unable to acquire the client lock
    /// * `ConfigError` - If the HTTP client is not initialized
    /// * `ConfigError` - If unable to serialize the JSON payload
    /// * `ConfigError` - If unable to get the global configuration
    /// * `ConfigError` - If the `user_id` is not found in the configuration
    /// * `NetworkError` - If the request fails to send or receive a response
    ///
    /// # Examples
    ///
    /// ```rust
    /// // GET request without payload
    /// let response = client.request(Method::GET, "/api/status", None).await?;
    ///
    /// // POST request with JSON payload
    /// let json = serde_json::json!({"key": "value"});
    /// let response = client.request(Method::POST, "/api/data", Some(json)).await?;
    /// ```
    pub async fn request(&self, method: Method, path: &str, json: Option<Value>) -> Result<Response, AgentError> {
        let client_guard = self.client.read().map_err(|e| {
            error!("Failed to acquire client read lock: {}", e);
            AgentError::LockError(format!("Cannot acquire client lock: {}", e))
        })?;

        let client = client_guard.as_ref().ok_or_else(|| {
            error!("HTTP client not initialized");
            AgentError::ConfigError("HTTP client not initialized".to_string())
        })?;

        let config = self.get_config()?;

        let request_url = format!("{}{}", config.base_url, path);
        debug!("Base url is {}, rest path is {}", config.base_url, path);

        let mut req = client.request(method.clone(), &request_url);
        if let Some(data) = &json {
            let json_str = serde_json::to_string(data).map_err(|e| {
                error!("Failed to serialize JSON: {}", e);
                AgentError::ConfigError(format!("Failed to serialize JSON: {}", e))
            })?;

            // Dynamically get user_id from config
            let user_id = AGENT_CONFIG
                .get_instance()
                .map_err(|e| {
                    error!("Failed to get global config: {}", e);
                    AgentError::ConfigError(format!("Failed to get global config: {}", e))
                })?
                .agent
                .user_id
                .clone()
                .ok_or_else(|| {
                    error!("agent.user_id field not found in config");
                    AgentError::ConfigError("agent.user_id field not found in config".to_string())
                })?;
            req = req.header("Content-Type", "application/json").header("User-Id", user_id).body(json_str);
        }

        info!("Sending {} request to {}", method.clone(), Self::mask_sensitive_info(&request_url));
        if json.is_some() {
            info!("Request contains JSON payload");
        }

        match req.send().await {
            Ok(response) => Ok(response),
            Err(e) => {
                error!("Request to {} failed: {}", request_url, e);
                Err(AgentError::NetworkError(format!("Request failed: {}", e)))
            },
        }
    }

    fn get_config(&self) -> Result<ClientConfig, AgentError> {
        self.config
            .read()
            .map_err(|e| {
                error!("Failed to acquire config read lock: {}", e);
                AgentError::LockError(format!("Cannot acquire config lock: {}", e))
            })
            .map(|config| config.clone())
    }
}
