use crate::agent_error::AgentError;
use crate::validate::validate_utils::validate_file;
use log::{error, info, debug};
use once_cell::sync::OnceCell;
use reqwest::{Client as ReqwestClient, Method, Proxy, Response};
use serde_json::Value;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use validator::Validate;

const CLIENT_CONNECTION_TIMEOUT: u64 = 60; // Client connection timeout in seconds

// Certificate configuration structure
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

// Client configuration structure, containing base configuration and optional certificate configuration
#[derive(Validate)]
#[derive(Clone, Debug)]
pub struct ClientConfig {
    #[validate(url)]
    base_url: String,
    #[validate(url)]
    proxy: Option<String>,
    cert_config: Option<CertConfig>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            proxy: None,
            cert_config: None,
        }
    }
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

    pub fn validate_config(&self) -> Result<(), AgentError> {
        if let Err(err) = self.validate() {
            return Err(AgentError::ConfigError(format!("Validation failed: {:?}", err)));
        }

        // If base_url starts with https, certificate configuration needs to be verified
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

        // Update configuration
        {
            let mut config_guard = instance
                .config
                .write()
                .map_err(|e| {
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
            let mut client_guard = instance
                .client
                .write()
                .map_err(|e| {
                    error!("Failed to acquire client lock: {}", e);
                    AgentError::LockError(format!("Cannot acquire client lock: {}", e))
                })?;
            *client_guard = Some(client);
        }

        Ok(instance)
    }

    fn create_client(config: &ClientConfig) -> Result<ReqwestClient, AgentError> {
        // Initialize client builder
        let mut builder = ReqwestClient::builder().timeout(Duration::from_secs(CLIENT_CONNECTION_TIMEOUT));

        if config.base_url.starts_with("https://") {
            if let Some(cert_config) = &config.cert_config {
                // Create SSL builder
                let mut ssl_builder = match SslAcceptor::mozilla_modern(SslMethod::tls()) {
                    Ok(builder) => builder,
                    Err(e) => {
                        error!("Failed to create SSL acceptor: {}", e);
                        return Err(AgentError::SslError(format!("Failed to create SSL acceptor: {}", e)));
                    }
                };

                // Set certificate and private key
                if let Err(e) = ssl_builder.set_certificate_file(&cert_config.cert_path, SslFiletype::PEM) {
                    error!("Failed to set certificate file: {}", e);
                    return Err(AgentError::SslError(format!("Failed to set certificate file: {}", e)));
                }
                if let Err(e) = ssl_builder.set_private_key_file(&cert_config.key_path, SslFiletype::PEM) {
                    error!("Failed to set private key file: {}", e);
                    return Err(AgentError::SslError(format!("Failed to set private key file: {}", e)));
                }
                if let Err(e) = ssl_builder.check_private_key() {
                    error!("Failed to check private key: {}", e);
                    return Err(AgentError::SslError(format!("Failed to check private key: {}", e)));
                }

                // Set CA certificate
                if let Err(e) = ssl_builder.set_ca_file(&cert_config.ca_path) {
                    error!("Failed to set CA file: {}", e);
                    return Err(AgentError::SslError(format!("Failed to set CA file: {}", e)));
                }

                // Create reqwest client
                let _ssl_context = ssl_builder.build();
                builder = match builder.use_native_tls() {
                    builder => builder,
                };
            }
        }

        // Configure proxy
        if let Some(proxy_url) = config.proxy.as_deref() {
            info!("Configuring HTTP client with proxy: {}", Self::mask_sensitive_info(proxy_url));

            let proxy = match Proxy::all(proxy_url) {
                Ok(proxy) => proxy,
                Err(e) => {
                    error!("Invalid proxy URL: {}", e);
                    return Err(AgentError::ConfigError(format!("Invalid proxy URL: {}", e)));
                }
            };

            builder = builder.proxy(proxy);
        }

        // Build client
        match builder.build() {
            Ok(client) => Ok(client),
            Err(e) => {
                let error_msg = format!("Failed to build HTTP client: {}", e);
                error!("{}", error_msg);
                Err(AgentError::ConfigError(error_msg))
            }
        }
    }

    /// Helper function: Mask sensitive information in proxy URL
    fn mask_sensitive_info(url: &str) -> String {
        url.split('@').last().map_or_else(|| url.to_string(), |masked| format!("***@{}", masked))
    }

    pub async fn request(&self, method: Method, path: &str, json: Option<Value>) -> Result<Response, AgentError> {
        let client_guard = self.client.read()
            .map_err(|e| {
                error!("Failed to acquire client read lock: {}", e);
                AgentError::LockError(format!("Cannot acquire client lock: {}", e))
            })?;

        let client = client_guard.as_ref()
            .ok_or_else(|| {
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
            req = req.header("Content-Type", "application/json").body(json_str);
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
            }
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
