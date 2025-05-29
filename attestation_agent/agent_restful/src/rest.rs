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

use crate::middlewares::rate_limit::{RateLimit, GLOBAL_LIMITER};
use crate::middlewares::request_logger::RequestLogger;
use crate::middlewares::security_headers::SecurityHeaders;
use crate::middlewares::trusted_proxies::TrustedProxies;
use actix_web::dev::Service;
use actix_web::middleware::{Condition, Logger, NormalizePath, TrailingSlash};
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer};
use agent_utils::validate_utils::{validate_bind_address, validate_file, validate_rest_path};
use agent_utils::AgentError;
use log::{error, info, warn};
use once_cell::sync::OnceCell;
use openssl::ssl::{SslAcceptor, SslAcceptorBuilder, SslFiletype, SslMethod};
use reqwest::Method;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use validator::Validate;

/// Constants used for rate limiting and connection control
const DEFAULT_PAYLOAD_SIZE: usize = 1024 * 1024 * 10; // 10MB
const MAX_CONNECTIONS: usize = 3; // Maximum concurrent connections

#[derive(Validate)]
#[derive(Clone, Debug)]
pub struct CertConfig {
    #[validate(custom(function = "validate_file"), required)]
    pub cert_path: Option<String>,
    #[validate(custom(function = "validate_file"), required)]
    pub key_path: Option<String>,
}

#[derive(Validate)]
#[derive(Clone, Debug)]
pub struct ServiceConfig {
    /// Whether to enable HTTPS server.
    pub enable_https: bool,
    /// Server port. If None, server will not be started.
    #[validate(required)]
    pub port: Option<u16>,
    /// Server binding address for listening to incoming connections.
    /// This must be specified before starting the server.
    #[validate(custom(function = "validate_bind_address"), required)]
    pub bind_address: Option<String>,
    /// List of trusted proxy addresses for handling forwarded headers.
    pub trusted_proxies: Vec<String>,

    pub cert_config: Option<CertConfig>,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        ServiceConfig {
            enable_https: false,
            port: None,
            bind_address: None,
            trusted_proxies: Vec::new(),
            cert_config: None,
        }
    }
}

impl ServiceConfig {
    /// Creates a new empty server configuration with default values.
    ///
    /// This creates a basic configuration instance with all fields set to default values.
    /// You'll need to configure at least a port and binding address before use.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use agent_restful::ServiceConfig;
    /// let config = ServiceConfig::new()
    ///     .with_port(8080)
    ///     .with_bind_address("127.0.0.1");
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets whether the HTTPS server should be enabled.
    ///
    /// When enabled, a valid HTTPS port, bind address, certificate path, and key path
    /// must also be configured. Even if HTTPS port is set, the server will not start
    /// unless HTTPS is explicitly enabled.
    ///
    /// # Parameters
    ///
    /// * `enable` - If true, enables HTTPS; otherwise uses HTTP
    pub fn with_enable_https(mut self, enable: bool) -> Self {
        self.enable_https = enable;
        self
    }

    /// Sets the server port to listen on.
    ///
    /// This port will be used for either HTTP or HTTPS depending on configuration.
    ///
    /// # Parameters
    ///
    /// * `port` - The port number to bind the server to
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Sets the server binding address.
    ///
    /// This address is used for both HTTP and HTTPS servers.
    /// Common values are "0.0.0.0" to bind to all interfaces or "127.0.0.1" for localhost only.
    ///
    /// # Parameters
    ///
    /// * `address` - The IP address to bind to (e.g., "127.0.0.1" or "0.0.0.0")
    pub fn with_bind_address(mut self, address: &str) -> Self {
        self.bind_address = Some(address.to_string());
        self
    }

    /// Sets the SSL certificate file path for HTTPS.
    ///
    /// Required when HTTPS is enabled. The file must exist and be readable.
    ///
    /// # Parameters
    ///
    /// * `path` - Path to the SSL certificate file in PEM format
    pub fn with_certificates(mut self, cert_path: &str, key_path: &str) -> Self {
        self.cert_config =
            Some(CertConfig { cert_path: Some(cert_path.to_string()), key_path: Some(key_path.to_string()) });
        self
    }

    fn validate_config(&self) -> Result<(), AgentError> {
        // First validate using the validator crate
        if let Err(e) = self.validate() {
            return Err(AgentError::ValidationError(e.to_string()));
        }

        // Then validate certificate configuration if HTTPS is enabled
        if self.enable_https {
            if self.cert_config.is_none() {
                return Err(AgentError::ConfigError(
                    "Certificate configuration must be specified for HTTPS".to_string(),
                ));
            }
            if let Some(cert_config) = &self.cert_config {
                if let Err(e) = cert_config.validate() {
                    return Err(AgentError::ValidationError(e.to_string()));
                }
            }
        }

        // Validate trusted proxies
        for proxy in &self.trusted_proxies {
            if proxy.trim().is_empty() {
                return Err(AgentError::ConfigError("Trusted proxy cannot be empty".to_string()));
            }
        }

        Ok(())
    }

    /// Adds a trusted proxy address to the configuration.
    ///
    /// Trusted proxies are servers that are allowed to modify forwarded headers
    /// such as X-Forwarded-For, X-Forwarded-Host, and X-Forwarded-Proto.
    ///
    /// # Parameters
    ///
    /// * `proxy_address` - The IP address of the proxy to trust
    ///
    /// # Returns
    ///
    /// * `Self` - The updated configuration with the proxy added
    pub fn add_trusted_proxy(mut self, proxy_address: &str) -> Self {
        self.trusted_proxies.push(proxy_address.to_string());
        self
    }

    /// Adds multiple trusted proxy addresses to the configuration.
    ///
    /// This method allows adding multiple proxy addresses at once.
    ///
    /// # Parameters
    ///
    /// * `proxies` - A vector of proxy addresses to trust
    ///
    /// # Returns
    ///
    /// * `Self` - The updated configuration with all proxies added
    pub fn with_trusted_proxies(mut self, proxies: Vec<&str>) -> Self {
        for proxy in proxies {
            self.trusted_proxies.push(proxy.to_string());
        }
        self
    }
}

/// Route item - Simplified direct use of handler functions
#[derive(Clone)]
struct Route {
    path: String,
    method: Method,
    handler_fn: Arc<dyn Fn() -> actix_web::Route + Send + Sync>,
}

/// REST service implementation that manages HTTP/HTTPS servers.
///
/// This service handles the lifecycle of the web servers, including startup,
/// shutdown, and routing configuration. It supports both HTTP and HTTPS servers
/// running simultaneously.
pub struct RestService {
    config: RwLock<ServiceConfig>,
    routes: RwLock<Vec<Route>>,
    shutdown_sender: Mutex<Option<tokio::sync::broadcast::Sender<()>>>,
    is_running: AtomicBool,
}

// Global singleton
static SERVICE_INSTANCE: OnceCell<Arc<RestService>> = OnceCell::new();

impl RestService {
    // Create default instance - private method
    fn default() -> Self {
        RestService {
            config: RwLock::new(ServiceConfig::default()),
            routes: RwLock::new(Vec::new()),
            shutdown_sender: Mutex::new(None),
            is_running: AtomicBool::new(false),
        }
    }

    /// Gets or creates the singleton instance of RestService.
    ///
    /// This method ensures only one instance of RestService exists in the application.
    /// The first call creates the instance, subsequent calls return references to the same instance.
    ///
    /// # Returns
    ///
    /// * `Arc<RestService>` - Thread-safe reference to the singleton instance
    ///
    /// # Example
    ///
    /// ```no_run
    /// use agent_restful::RestService;
    /// let service = RestService::instance();
    /// ```
    pub fn instance() -> Arc<Self> {
        SERVICE_INSTANCE.get_or_init(|| Arc::new(Self::default())).clone()
    }

    // Get configuration
    fn get_config(&self) -> Result<ServiceConfig, AgentError> {
        self.config
            .read()
            .map_err(|e| AgentError::LockError(format!("Cannot acquire config lock: {}", e)))
            .map(|config| config.clone())
    }

    /// Configures the REST service with the provided configuration.
    ///
    /// This method applies the given configuration to the REST service singleton,
    /// including HTTP/HTTPS server settings, proxy setup, and security options.
    /// The configuration is validated before being applied.
    ///
    /// # Parameters
    ///
    /// * `config` - The `ServiceConfig` to apply
    ///
    /// # Returns
    ///
    /// * `Result<Arc<Self>, AgentError>` - Success returns a reference to the configured service,
    ///   failure returns an appropriate error
    ///
    /// # Example
    ///
    /// ```no_run
    /// use agent_restful::{ServiceConfig, RestService};
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let config = ServiceConfig::new()
    ///         .with_port(8080)
    ///         .with_bind_address("127.0.0.1");
    ///     let service = RestService::configure(config)?;
    ///     Ok(())
    /// }
    /// ```
    pub fn configure(config: ServiceConfig) -> Result<Arc<Self>, AgentError> {
        let instance = Self::instance();

        if let Err(e) = config.validate_config() {
            let err = AgentError::ConfigError(e.to_string());
            error!("{}", err);
            return Err(err);
        }
        {
            let mut config_guard = instance.config.write().map_err(|e| {
                let err = AgentError::LockError(format!("Cannot acquire config lock for update: {}", e));
                error!("{}", err);
                err
            })?;

            *config_guard = config;
            info!("Server configuration updated");
        }

        Ok(instance.clone())
    }

    /// Registers a route handler for a specific HTTP method and path.
    ///
    /// This method allows registering custom handlers for various HTTP methods
    /// (GET, POST, PUT, DELETE) at specified paths. The handler is called when
    /// a matching request is received.
    ///
    /// # Path Parameters
    ///
    /// Path parameters can be defined using the `{param_name}` syntax and
    /// extracted with the `get_path_param` method.
    ///
    /// # Parameters
    ///
    /// * `method` - The HTTP method (GET, POST, PUT, DELETE)
    /// * `path` - The URL path pattern (e.g., "/api/users/{id}")
    /// * `handler` - A function taking an HttpRequest and optional JSON payload,
    ///   returning an HttpResponse
    ///
    /// # Returns
    ///
    /// * `Result<(), AgentError>` - Success or error if path is invalid or conflicting
    ///
    /// # Example
    ///
    /// ```no_run
    /// use agent_restful::RestService;
    /// use serde_json::json;
    /// use reqwest::Method;
    /// use actix_web::{HttpRequest, HttpResponse};
    /// let service = RestService::instance();
    /// service.register(Method::GET, "/users/{id}", |req: HttpRequest, _| {
    ///     let id = RestService::get_path_param(&req, "id").unwrap_or_default();
    ///     HttpResponse::Ok().json(json!({"id": id}))
    /// }).unwrap();
    /// ```
    pub fn register<F>(&self, method: Method, path: &str, handler: F) -> Result<(), AgentError>
    where
        F: Fn(HttpRequest, Option<Value>) -> HttpResponse + Send + Sync + 'static,
    {
        let handler = Arc::new(handler);
        let handler_fn = self.create_method_handler(method.clone(), handler)?;
        self.add_route(method.clone(), path, handler_fn)
    }

    fn create_method_handler<F>(
        &self,
        method: Method,
        handler: Arc<F>,
    ) -> Result<Arc<dyn Fn() -> actix_web::Route + Send + Sync>, AgentError>
    where
        F: Fn(HttpRequest, Option<Value>) -> HttpResponse + Send + Sync + 'static,
    {
        let handler_fn = match method {
            Method::GET => self.create_get_handler(handler),
            Method::POST => self.create_post_handler(handler),
            Method::PUT => self.create_put_handler(handler),
            Method::DELETE => self.create_delete_handler(handler),
            _ => {
                return Err(AgentError::ConfigError(format!("Unsupported method: {}", method)));
            },
        };

        Ok(handler_fn)
    }

    fn create_get_handler<F>(&self, handler: Arc<F>) -> Arc<dyn Fn() -> actix_web::Route + Send + Sync>
    where
        F: Fn(HttpRequest, Option<Value>) -> HttpResponse + Send + Sync + 'static,
    {
        Arc::new(move || {
            let handler = Arc::clone(&handler);
            web::get().to(move |req: HttpRequest| {
                let handler = Arc::clone(&handler);
                async move { handler(req, None) }
            })
        })
    }

    fn create_post_handler<F>(&self, handler: Arc<F>) -> Arc<dyn Fn() -> actix_web::Route + Send + Sync>
    where
        F: Fn(HttpRequest, Option<Value>) -> HttpResponse + Send + Sync + 'static,
    {
        Arc::new(move || {
            let handler = Arc::clone(&handler);
            web::post().to(move |req: HttpRequest, body: Option<web::Json<Value>>| {
                let handler = Arc::clone(&handler);
                let data = body.map(|b| b.into_inner());
                async move { handler(req, data) }
            })
        })
    }

    fn create_put_handler<F>(&self, handler: Arc<F>) -> Arc<dyn Fn() -> actix_web::Route + Send + Sync>
    where
        F: Fn(HttpRequest, Option<Value>) -> HttpResponse + Send + Sync + 'static,
    {
        Arc::new(move || {
            let handler = Arc::clone(&handler);
            web::put().to(move |req: HttpRequest, body: Option<web::Json<Value>>| {
                let handler = Arc::clone(&handler);
                let data = body.map(|b| b.into_inner());
                async move { handler(req, data) }
            })
        })
    }

    fn create_delete_handler<F>(&self, handler: Arc<F>) -> Arc<dyn Fn() -> actix_web::Route + Send + Sync>
    where
        F: Fn(HttpRequest, Option<Value>) -> HttpResponse + Send + Sync + 'static,
    {
        Arc::new(move || {
            let handler = Arc::clone(&handler);
            web::delete().to(move |req: HttpRequest| {
                let handler = Arc::clone(&handler);
                async move { handler(req, None) }
            })
        })
    }

    fn add_route(
        &self,
        method: Method,
        path: &str,
        handler_fn: Arc<dyn Fn() -> actix_web::Route + Send + Sync>,
    ) -> Result<(), AgentError> {
        if let Err(e) = self.validate_path(path, &method) {
            error!("{}", e);
            return Err(e);
        }

        let mut routes_guard =
            self.routes.write().map_err(|e| AgentError::LockError(format!("Failed to acquire routes lock: {}", e)))?;

        routes_guard.push(Route { path: path.to_string(), method: method.clone(), handler_fn });

        info!("Registered route: {} {}", method.clone(), path);
        Ok(())
    }

    fn get_routes(&self) -> Result<Vec<Route>, AgentError> {
        self.routes
            .read()
            .map_err(|e| AgentError::LockError(format!("Cannot acquire routes lock: {}", e)))
            .map(|routes| routes.clone())
    }

    fn validate_path(&self, path: &str, method: &Method) -> Result<(), AgentError> {
        validate_rest_path(path)?;
        self.check_route_conflicts(path, method)?;
        Ok(())
    }

    fn check_route_conflicts(&self, path: &str, method: &Method) -> Result<(), AgentError> {
        if let Ok(routes) = self.get_routes() {
            for route in routes {
                if self.routes_conflict(&route.path, path) && &route.method == method {
                    return Err(AgentError::ConfigError(format!(
                        "Route conflict detected: '{} {}' conflicts with existing route. \
                            Registration rejected.",
                        method, path
                    )));
                }
            }
        }

        Ok(())
    }

    fn routes_conflict(&self, path1: &str, path2: &str) -> bool {
        if path1 == path2 {
            return true;
        }

        let segments1: Vec<&str> = path1.split('/').filter(|s| !s.is_empty()).collect();
        let segments2: Vec<&str> = path2.split('/').filter(|s| !s.is_empty()).collect();

        if segments1.len() != segments2.len() {
            return false;
        }

        for (seg1, seg2) in segments1.iter().zip(segments2.iter()) {
            if !seg1.starts_with('{') && !seg2.starts_with('{') && seg1 != seg2 {
                return false;
            }
        }

        true
    }

    /// Starts the REST service server based on the current configuration.
    ///
    /// This method starts HTTP or HTTPS servers according to the configuration.
    /// The server begins listening for incoming requests on the configured
    /// port and binding address.
    ///
    /// # Returns
    ///
    /// * `Result<(), AgentError>` - Success or error if server cannot start
    ///
    /// # Example
    ///
    /// ```no_run
    /// // Configure and start the server
    /// use agent_restful::{ServiceConfig, RestService};
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let service = RestService::instance();
    ///     let config = ServiceConfig::new()
    ///         .with_port(8080)
    ///         .with_bind_address("127.0.0.1");
    ///     RestService::configure(config)?;
    ///     service.start_server().await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn start_server(&self) -> Result<(), AgentError> {
        info!("Starting REST service server");
        if self.is_running.load(Ordering::SeqCst) {
            let err = AgentError::ServerStateError("Server is already running".to_string());
            error!("{}", err);
            return Err(err);
        }

        let config = self.get_config()?;

        self.start_server_impl(config).await
    }

    async fn start_server_impl(&self, config: ServiceConfig) -> Result<(), AgentError> {
        let (tx, rx) = tokio::sync::broadcast::channel(1);
        self.save_broadcast_shutdown_sender(tx)?;

        let bind_address = config
            .bind_address
            .as_ref()
            .ok_or_else(|| AgentError::ConfigError("Bind address not configured".to_string()))?;

        let routes = self.get_routes()?;

        if config.enable_https {
            let https_addr = format!("{}:{}", bind_address, config.port.unwrap());
            info!("Starting HTTPS server on {}", https_addr);

            let cert_path = PathBuf::from(config.cert_config.as_ref().unwrap().cert_path.as_ref().unwrap());
            let key_path = PathBuf::from(config.cert_config.as_ref().unwrap().key_path.as_ref().unwrap());

            self.start_https_server(&https_addr, &cert_path, &key_path, rx, config.clone()).await?;
        } else {
            let http_addr = format!("{}:{}", bind_address, config.port.unwrap());
            info!("Starting HTTP server on {}", http_addr);
            self.start_http_server(&http_addr, routes.clone(), rx.resubscribe(), config.clone()).await?;
        }

        self.is_running.store(true, Ordering::SeqCst);

        Ok(())
    }

    async fn start_https_server(
        &self,
        https_addr: &str,
        cert_path: &PathBuf,
        key_path: &PathBuf,
        rx: tokio::sync::broadcast::Receiver<()>,
        config: ServiceConfig,
    ) -> Result<(), AgentError> {
        let routes = match self.get_routes() {
            Ok(routes) => routes,
            Err(e) => {
                error!("Failed to get routes: {}", e);
                return Err(e);
            },
        };

        let ssl_builder = match self.create_ssl_builder(cert_path, key_path) {
            Ok(builder) => builder,
            Err(e) => {
                error!("Failed to create ssl builder: {}", e);
                return Err(e);
            },
        };

        info!("Starting HTTPS server on {}", https_addr);

        self.start_https_server_impl(https_addr, ssl_builder, routes, rx, config)
    }

    fn start_https_server_impl(
        &self,
        https_addr: &str,
        ssl_builder: SslAcceptorBuilder,
        routes: Vec<Route>,
        rx: tokio::sync::broadcast::Receiver<()>,
        config: ServiceConfig,
    ) -> Result<(), AgentError> {
        let https_addr = https_addr.to_string();
        let mut rx = rx;

        let server = HttpServer::new(move || create_app(&config, &routes))
            .max_connections(MAX_CONNECTIONS)
            .bind_openssl(&https_addr, ssl_builder)
            .map_err(|e| AgentError::NetworkError(format!("HTTPS server binding failed {}: {}", https_addr, e)))?
            .run();

        tokio::spawn(async move {
            tokio::select! {
                result = server => {
                    if let Err(e) = result {
                        return Err(AgentError::NetworkError(
                            format!("HTTPS server error: {}", e)
                        ));
                    }
                },
                _ = rx.recv() => {
                    info!("HTTPS server shutting down gracefully");
                }
            }

            Ok(())
        });

        Ok(())
    }

    fn create_ssl_builder(&self, cert_path: &PathBuf, key_path: &PathBuf) -> Result<SslAcceptorBuilder, AgentError> {
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())
            .map_err(|e| AgentError::ConfigError(format!("Failed to create SSL configuration: {}", e)))?;

        builder
            .set_private_key_file(key_path, SslFiletype::PEM)
            .map_err(|e| AgentError::ConfigError(format!("Failed to set SSL private key: {}", e)))?;

        builder
            .set_certificate_chain_file(cert_path)
            .map_err(|e| AgentError::ConfigError(format!("Failed to set SSL certificate: {}", e)))?;

        Ok(builder)
    }

    fn save_broadcast_shutdown_sender(&self, tx: tokio::sync::broadcast::Sender<()>) -> Result<(), AgentError> {
        let mut sender_guard = self
            .shutdown_sender
            .lock()
            .map_err(|e| AgentError::LockError(format!("Cannot acquire shutdown signal lock: {}", e)))?;
        *sender_guard = Some(tx);
        Ok(())
    }

    /// Stops the running REST service servers.
    ///
    /// This method gracefully shuts down all running HTTP and HTTPS servers
    /// by sending a shutdown signal. Ongoing requests are allowed to complete.
    ///
    /// # Returns
    ///
    /// * `Result<(), AgentError>` - Success or error if shutdown fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// // Shut down the server
    /// use agent_restful::RestService;
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let service = RestService::instance();
    ///     service.stop_server().await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn stop_server(&self) -> Result<(), AgentError> {
        info!("Stopping REST service server");

        if !self.is_running.load(Ordering::SeqCst) {
            info!("Server already stopped, nothing to do");
            return Ok(());
        }

        match self.take_broadcast_shutdown_sender()? {
            Some(sender) => {
                self.is_running.store(false, Ordering::SeqCst);
                self.send_broadcast_shutdown_signal(sender).await?;
                info!("Server stopped successfully");
                Ok(())
            },
            None => {
                let err = AgentError::ServerStateError("Shutdown signal not found".to_string());
                error!("{}", err);
                self.is_running.store(false, Ordering::SeqCst);
                Err(err)
            },
        }
    }

    fn take_broadcast_shutdown_sender(&self) -> Result<Option<tokio::sync::broadcast::Sender<()>>, AgentError> {
        let mut sender_guard = self
            .shutdown_sender
            .lock()
            .map_err(|e| AgentError::LockError(format!("Cannot acquire shutdown signal lock: {}", e)))?;

        Ok(sender_guard.take())
    }

    async fn send_broadcast_shutdown_signal(
        &self,
        sender: tokio::sync::broadcast::Sender<()>,
    ) -> Result<(), AgentError> {
        if sender.send(()).is_err() {
            return Err(AgentError::ServerStateError("Failed to send shutdown signal: no receivers".to_string()));
        }

        Ok(())
    }

    async fn start_http_server(
        &self,
        http_addr: &str,
        routes: Vec<Route>,
        rx: tokio::sync::broadcast::Receiver<()>,
        config: ServiceConfig,
    ) -> Result<(), AgentError> {
        info!("Starting HTTP server on {}", http_addr);
        let http_addr = http_addr.to_string();
        let mut rx = rx;

        tokio::spawn(async move {
            let server = HttpServer::new(move || create_app(&config, &routes))
                .max_connections(MAX_CONNECTIONS)
                .bind(&http_addr)
                .map_err(|e| AgentError::NetworkError(format!("HTTP server binding failed {}: {}", http_addr, e)))?
                .run();

            tokio::select! {
                result = server => {
                    if let Err(e) = result {
                        return Err(AgentError::NetworkError(
                            format!("HTTP server error: {}", e)
                        ));
                    }
                },
                _ = rx.recv() => {
                    info!("HTTP server shutting down gracefully");
                }
            }

            Ok(())
        });
        Ok(())
    }

    /// Extract path parameters from request
    ///
    /// Extracts a named parameter from the URL path based on the route pattern.
    /// For example, if a route is registered as "/users/{id}", this method
    /// can extract the "id" value from a request to "/users/123".
    ///
    /// # Parameters
    ///
    /// * `req` - The HTTP request
    /// * `name` - The parameter name to extract
    ///
    /// # Returns
    ///
    /// * `Option<String>` - The parameter value if it exists, otherwise None
    ///
    /// # Example
    ///
    /// ```no_run
    /// use agent_restful::RestService;
    /// use serde_json::json;
    /// use reqwest::Method;
    /// use actix_web::{HttpRequest, HttpResponse};
    /// let service = RestService::instance();
    /// service.register(Method::GET, "/users/{id}", |req: HttpRequest, _| {
    ///     let id = RestService::get_path_param(&req, "id").unwrap_or_default();
    ///     HttpResponse::Ok().json(json!({"id": id}))
    /// }).unwrap();
    /// ```
    pub fn get_path_param(req: &HttpRequest, name: &str) -> Option<String> {
        req.match_info().get(name).map(String::from)
    }
}

fn create_app(
    config: &ServiceConfig,
    routes: &Vec<Route>,
) -> App<
    impl actix_web::dev::ServiceFactory<
        actix_web::dev::ServiceRequest,
        Config = (),
        Response = actix_web::dev::ServiceResponse<actix_web::body::BoxBody>,
        Error = actix_web::Error,
        InitError = (),
    >,
> {
    let json_config = web::JsonConfig::default().limit(DEFAULT_PAYLOAD_SIZE).content_type(|_| true);

    let app = App::new()
        .app_data(json_config)
        .app_data(GLOBAL_LIMITER.clone())
        .wrap(RateLimit)
        .wrap(Logger::default())
        .wrap(RequestLogger::new())
        .wrap(SecurityHeaders::new())
        .wrap(TrustedProxies::new(config))
        .wrap(Condition::new(true, NormalizePath::new(TrailingSlash::Trim)))
        .wrap_fn(|req, srv| {
            let fut = srv.call(req);
            async move {
                let result = fut.await;
                if let Err(ref e) = result {
                    error!("Request processing error: {}", e);
                }
                result.map(|res| res.map_body(|_head, body| actix_web::body::BoxBody::new(body)))
            }
        });

    let app = app
        .route("/health", web::get().to(|| async { HttpResponse::Ok().json(json!({"status": "healthy"})) }))
        .route("/debug", web::get().to(|| async { HttpResponse::Ok().json(json!({"status": "debug_ok"})) }));

    let mut app_with_routes = app;
    for route in routes {
        app_with_routes = app_with_routes.route(&route.path, (route.handler_fn)());
    }

    app_with_routes.default_service(web::route().to(|| async {
        warn!("Request to non-existent path received");
        HttpResponse::NotFound().content_type("application/json").json(json!({
            "error": "Path not found",
            "code": 404
        }))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{http::Method, HttpRequest, HttpResponse};
    use serde_json::json;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::TempDir;

    fn create_test_instance() -> Arc<RestService> {
        Arc::new(RestService::default())
    }

    fn verify_file_exists(path: &std::path::Path, file_type: &str) {
        assert!(path.exists(), "{} file does not exist, path: {:?}", file_type, path);
        assert!(path.is_file(), "{} path is not a file: {:?}", file_type, path);
    }

    fn generate_test_certificate() -> (PathBuf, PathBuf, TempDir) {
        let temp_dir = TempDir::new().expect("Cannot create temporary directory");
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        let status = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                key_path.to_str().unwrap(),
                "-out",
                cert_path.to_str().unwrap(),
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=localhost",
            ])
            .stderr(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .status()
            .expect("Cannot execute openssl command");

        assert!(status.success(), "openssl command execution failed");

        verify_file_exists(&cert_path, "certificate");
        verify_file_exists(&key_path, "private key");

        (cert_path, key_path, temp_dir)
    }

    #[tokio::test]
    async fn test_server_lifecycle() {
        // 1. Test server already running condition
        let service = create_test_instance();
        service.is_running.store(true, std::sync::atomic::Ordering::SeqCst);

        let result = service.start_server().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Server is already running"));

        // 2. Test invalid configuration
        service.is_running.store(false, std::sync::atomic::Ordering::SeqCst);

        let invalid_config = ServiceConfig::new();
        {
            let mut config_guard = service.config.write().unwrap();
            *config_guard = invalid_config;
        }

        let result = service.start_server().await;
        assert!(result.is_err());

        // 3. Test port conflict
        let service2 = create_test_instance();

        // First bind a port to simulate occupation
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        // Set service to use the same port
        let config = ServiceConfig::new().with_port(port).with_bind_address("127.0.0.1");

        {
            let mut config_guard = service2.config.write().unwrap();
            *config_guard = config;
        }

        // Try to start service, should fail due to port being in use
        let _result = service2.start_server().await;

        // 4. Test stopping non-running server
        let service3 = create_test_instance();
        service3.is_running.store(false, std::sync::atomic::Ordering::SeqCst);

        let result = service3.stop_server().await;
        assert!(result.is_ok(), "Stopping a non-running server should succeed");

        // 5. Test broadcast signal handling
        let service4 = create_test_instance();
        service4.is_running.store(true, std::sync::atomic::Ordering::SeqCst);

        // Manually create and save broadcast sender
        let (tx, _rx) = tokio::sync::broadcast::channel(1);
        service4.save_broadcast_shutdown_sender(tx.clone()).unwrap();

        // Send broadcast signal - test direct server stop functionality
        let stop_result = service4.stop_server().await;
        assert!(stop_result.is_ok(), "Stopping a running server should succeed");

        // Release resources
        drop(listener);
    }

    #[tokio::test]
    async fn test_server_config_alternative_methods() {
        // Test HTTP configuration methods
        let http_config = ServiceConfig::new().with_port(8080);
        assert_eq!(http_config.port, Some(8080));

        // Test HTTPS configuration methods
        let https_config = ServiceConfig::new().with_port(8443);
        assert_eq!(https_config.port, Some(8443));

        // Test certificate configuration
        let (cert_path, key_path, _temp_dir) = generate_test_certificate();
        let cert_config =
            ServiceConfig::new().with_certificates(cert_path.to_str().unwrap(), key_path.to_str().unwrap());
        assert!(cert_config.cert_config.is_some());
    }

    #[tokio::test]
    async fn test_server_implementation_functions() {
        let service = create_test_instance();

        let route_handler = |_: HttpRequest, _: Option<Value>| HttpResponse::Ok().json(json!({"status": "test"}));
        service.register(Method::GET, "/test-route", route_handler).unwrap();
        let routes = service.get_routes().unwrap();

        let basic_config = ServiceConfig::new().with_port(0).with_bind_address("127.0.0.1");
        let _app = create_app(&basic_config, &routes);

        let (tx, rx) = tokio::sync::broadcast::channel::<()>(1);

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let http_addr = format!("127.0.0.1:{}", port);
        service.start_http_server(&http_addr, routes.clone(), rx, basic_config.clone()).await.unwrap();

        let _ = tx.send(());

        let (https_tx, https_rx) = tokio::sync::broadcast::channel::<()>(1);
        let (cert_path, key_path, _temp_dir) = generate_test_certificate();
        let ssl_builder = service.create_ssl_builder(&cert_path, &key_path).unwrap();

        let https_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let https_addr = format!("127.0.0.1:{}", https_listener.local_addr().unwrap().port());
        drop(https_listener);

        service.start_https_server_impl(&https_addr, ssl_builder, routes, https_rx, basic_config).unwrap();
        let _ = https_tx.send(());
    }

    #[tokio::test]
    async fn test_validate_path() {
        let service = create_test_instance();
        let method = Method::GET;

        // Test Group 1: Basic Path Format Validation
        // 1.1 - Valid paths should pass
        assert!(service.validate_path("/valid/path", &method).is_ok(), "Valid path should pass validation");
        assert!(service.validate_path("/", &method).is_ok(), "Root path should pass validation");
        assert!(
            service.validate_path("/with-dash/and_underscore", &method).is_ok(),
            "Path with dashes and underscores should pass validation"
        );

        // 1.2 - Empty path should fail
        let empty_result = service.validate_path("", &method);
        assert!(empty_result.is_err(), "Empty path should fail");
        assert!(
            empty_result.unwrap_err().to_string().contains("cannot be empty"),
            "Error message should mention that path is empty"
        );

        // 1.3 - Path not starting with '/' should fail
        let no_slash_result = service.validate_path("invalid/path", &method);
        assert!(no_slash_result.is_err(), "Path not starting with '/' should fail");
        assert!(
            no_slash_result.unwrap_err().to_string().contains("must start with '/'"),
            "Error message should mention needing to start with '/'"
        );

        // 1.4 - Path containing control characters should fail
        let control_char_result = service.validate_path("/invalid\npath", &method);
        assert!(control_char_result.is_err(), "Path containing control characters should fail");
        assert!(
            control_char_result.unwrap_err().to_string().contains("invalid control characters"),
            "Error message should mention illegal control characters"
        );

        // 1.5 - Path containing query parameters or fragments should fail
        let query_result = service.validate_path("/path?query=value", &method);
        assert!(query_result.is_err(), "Path containing query parameters should fail");
        assert!(
            query_result.unwrap_err().to_string().contains("should not contain query parameters"),
            "Error message should mention query parameters not allowed"
        );

        let fragment_result = service.validate_path("/path#fragment", &method);
        assert!(fragment_result.is_err(), "Path containing fragments should fail");
        assert!(
            fragment_result.unwrap_err().to_string().contains("should not contain query parameters or fragments"),
            "Error message should mention fragments not allowed"
        );

        // Test Group 2: Path Parameter Validation
        // 2.1 - Valid path parameters should pass
        assert!(
            service.validate_path("/users/{id}", &method).is_ok(),
            "Path with valid parameters should pass validation"
        );
        assert!(
            service.validate_path("/users/{id}/posts/{post_id}", &method).is_ok(),
            "Path with multiple valid parameters should pass validation"
        );

        // 2.2 - Nested braces should fail
        let nested_braces_result = service.validate_path("/users/{{id}}", &method);
        assert!(nested_braces_result.is_err(), "Nested braces should fail");
        assert!(
            nested_braces_result.unwrap_err().to_string().contains("Nested braces are not allowed"),
            "Error message should mention nested braces not allowed"
        );

        // 2.3 - Unmatched braces should fail
        let unmatched_open_result = service.validate_path("/users/{id", &method);
        assert!(unmatched_open_result.is_err(), "Unclosed braces should fail");
        assert!(
            unmatched_open_result.unwrap_err().to_string().contains("Unmatched braces"),
            "Error message should mention unmatched braces"
        );

        let unmatched_close_result = service.validate_path("/users/id}", &method);
        assert!(unmatched_close_result.is_err(), "Unopened closing brace should fail");
        assert!(
            unmatched_close_result.unwrap_err().to_string().contains("Unmatched closing brace"),
            "Error message should mention unmatched closing brace"
        );

        // 2.4 - Empty parameter name should fail
        let empty_param_result = service.validate_path("/users/{}", &method);
        assert!(empty_param_result.is_err(), "Empty parameter name should fail");
        assert!(
            empty_param_result.unwrap_err().to_string().contains("Empty parameter name"),
            "Error message should mention empty parameter name"
        );

        // 2.5 - Duplicate parameter name should fail
        let duplicate_param_result = service.validate_path("/users/{id}/profile/{id}", &method);
        assert!(duplicate_param_result.is_err(), "Duplicate parameter name should fail");
        assert!(
            duplicate_param_result.unwrap_err().to_string().contains("Duplicate parameter name"),
            "Error message should mention duplicate parameter name"
        );

        // 2.6 - Invalid characters in parameter name should fail
        let invalid_param_char_result = service.validate_path("/users/{invalid-name}", &method);
        assert!(invalid_param_char_result.is_err(), "Parameter name containing invalid characters should fail");
        assert!(
            invalid_param_char_result.unwrap_err().to_string().contains("Invalid character"),
            "Error message should mention invalid characters in parameter name"
        );

        // Test Group 3: Route Conflict Detection
        // First register a route, then test for conflicts
        service
            .register(Method::GET, "/api/resource/{id}", |_: HttpRequest, _: Option<Value>| HttpResponse::Ok().finish())
            .unwrap();

        // 3.1 - Exactly same path with same method should detect conflict
        let same_path_result = service.validate_path("/api/resource/{id}", &method);
        assert!(same_path_result.is_err(), "Same path should detect conflict");
        assert!(
            same_path_result.unwrap_err().to_string().contains("conflict"),
            "Error message should mention route conflict"
        );

        // 3.2 - Same path structure but different parameter names with same method should detect conflict
        let same_structure_result = service.validate_path("/api/resource/{resource_id}", &method);
        assert!(same_structure_result.is_err(), "Path with same structure should detect conflict");
        assert!(
            same_structure_result.unwrap_err().to_string().contains("conflict"),
            "Error message should mention route conflict"
        );

        // 3.3 - Same path but different method should not detect conflict
        let diff_method_result = service.validate_path("/api/resource/{id}", &Method::POST);
        assert!(diff_method_result.is_ok(), "Same path but different method should pass validation");

        // 3.4 - Paths with different structure should not detect conflict
        assert!(
            service.validate_path("/api/different/path", &method).is_ok(),
            "Path with different structure should pass validation"
        );
        assert!(
            service.validate_path("/api/resource/{id}/subresource", &method).is_ok(),
            "Path with extra segment should pass validation"
        );
        assert!(service.validate_path("/api", &method).is_ok(), "Path with fewer segments should pass validation");
    }

    #[tokio::test]
    async fn test_server_config_comprehensive() {
        // Test configuration without ports
        let config_no_ports = ServiceConfig::new().with_bind_address("127.0.0.1");

        let result = config_no_ports.validate_config();
        assert!(result.is_err(), "Config without ports should fail validation");
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("port"), "Error message should mention missing port configuration");

        // Test configuration without bind address
        let config_no_bind = ServiceConfig::new().with_port(8080);

        let result = config_no_bind.validate_config();
        assert!(result.is_err(), "Config without bind address should fail validation");

        // Test valid HTTP configuration (default)
        let config_valid_http = ServiceConfig::new().with_port(8080).with_bind_address("127.0.0.1");

        let result = config_valid_http.validate_config();
        assert!(result.is_ok(), "Valid HTTP config should pass validation");

        // Test HTTPS configuration missing certificate
        let config_https_no_cert =
            ServiceConfig::new().with_port(8443).with_enable_https(true).with_bind_address("127.0.0.1");

        let result = config_https_no_cert.validate_config();
        assert!(result.is_err(), "HTTPS config without certs should fail validation");

        let (cert_path, key_path, temp_dir) = generate_test_certificate();

        // Test valid HTTPS configuration
        let config_valid_https = ServiceConfig::new()
            .with_port(8443)
            .with_enable_https(true)
            .with_bind_address("127.0.0.1")
            .with_certificates(cert_path.to_str().unwrap(), key_path.to_str().unwrap());

        let result = config_valid_https.validate_config();
        assert!(result.is_ok(), "Valid HTTPS config should pass validation");

        drop(temp_dir);
    }

    #[tokio::test]
    async fn test_end_to_end_server_operation() {
        let instance = create_test_instance();
        instance.is_running.store(false, Ordering::SeqCst);

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let http_port = listener.local_addr().unwrap().port();
        drop(listener);

        instance
            .register(Method::GET, "/test_operation", |_, _| HttpResponse::Ok().json(json!({"success": true})))
            .expect("Should register route");

        let config = ServiceConfig::new().with_port(http_port).with_bind_address("127.0.0.1");

        {
            let mut config_guard = instance.config.write().unwrap();
            *config_guard = config.clone();
        }

        let server_result = instance.start_server().await;
        assert!(server_result.is_ok());

        tokio::time::sleep(Duration::from_millis(100)).await;

        let url = format!("http://127.0.0.1:{}/test_operation", http_port);
        let client = reqwest::Client::builder().timeout(Duration::from_secs(2)).build().unwrap();

        let response = client.get(&url).send().await.expect("Request should succeed");
        assert_eq!(response.status(), reqwest::StatusCode::OK);

        let body: Value = response.json().await.expect("Response should be JSON");
        assert_eq!(body["success"], json!(true));

        instance.stop_server().await.unwrap();
    }

    #[tokio::test]
    async fn test_timeout_behavior() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let config = ServiceConfig::new().with_port(port).with_bind_address("127.0.0.1");

        let service = create_test_instance();
        service.is_running.store(false, Ordering::SeqCst);

        {
            let mut config_guard = service.config.write().unwrap();
            *config_guard = config;
        }

        let server_result = service.start_server().await;
        assert!(server_result.is_ok());

        tokio::time::sleep(Duration::from_millis(100)).await;

        let client = reqwest::Client::new();
        let response =
            client.get(&format!("http://127.0.0.1:{}/health", port)).timeout(Duration::from_secs(2)).send().await;

        assert!(response.is_ok());

        service.stop_server().await.unwrap();
    }

    #[tokio::test]
    async fn test_invalid_json_payload_handling() {
        let service = create_test_instance();
        service.is_running.store(false, Ordering::SeqCst);

        service
            .register(Method::POST, "/json-test", |_: HttpRequest, body: Option<Value>| {
                if body.is_none() {
                    return HttpResponse::BadRequest().body("Invalid JSON payload");
                }
                HttpResponse::Ok().json(body.unwrap())
            })
            .unwrap();

        // Get an available port
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            // Important: Keep the port occupied until configuration is complete
            port
        };

        let config = ServiceConfig::new().with_port(port).with_bind_address("127.0.0.1");

        {
            let mut config_guard = service.config.write().unwrap();
            *config_guard = config;
        }

        // Start the server
        let server_result = service.start_server().await;
        assert!(server_result.is_ok());

        // Increase wait time to ensure server is fully started
        tokio::time::sleep(Duration::from_millis(500)).await;

        let client = reqwest::Client::builder().timeout(Duration::from_secs(5)).build().unwrap();
        let test_url = format!("http://127.0.0.1:{}/json-test", port);

        // Add retry logic to handle intermittent connection issues
        let mut response = None;
        for retry in 0..3 {
            // Try up to 3 times
            match client.post(&test_url).body("{invalid-json}").send().await {
                Ok(resp) => {
                    response = Some(resp);
                    break;
                },
                Err(e) => {
                    // If connection error, wait and retry
                    eprintln!("Connection failed, retrying: {} (attempt {})", e, retry + 1);
                    tokio::time::sleep(Duration::from_millis(300)).await;
                },
            }
        }

        // Check if we got a response
        let response = response.expect("Failed to connect to server even after retries");
        assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
        let body = response.text().await.unwrap();
        assert!(body.contains("Invalid JSON payload"));

        let stop_result = service.stop_server().await;
        assert!(stop_result.is_ok());
    }
}
