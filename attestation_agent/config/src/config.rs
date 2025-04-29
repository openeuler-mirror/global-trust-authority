use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use serde_json;
use config_manager::ConfigSingleton;

// TPM Basic Configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TpmBaseConfig {
    pub tcti_config: String,              // TCTI configuration string
    pub ak_handle: Option<u32>,           // AK handle
    pub ak_nv_index: Option<u32>,         // AK NV index
    pub pcr_selections: Option<PcrSelection>, // PCR selection list
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PcrSelection {
    pub banks: Vec<u32>,
    pub hash_algo: String,
}

// TPM Plugin Configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TpmConfig {
    #[serde(flatten)]
    pub tpm_base: TpmBaseConfig,          // Contains basic TPM configuration
    pub log_file_path: String,           // Event log path
}

// IMA Configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ImaConfig {
    #[serde(flatten)]
    pub tpm_base: TpmBaseConfig,          // Contains basic TPM configuration
    pub log_file_path: String,                 // IMA log path
    pub template_name: Option<String>,    // IMA template name
}

// DIM Configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DimConfig {
    #[serde(flatten)]
    pub tpm_base: TpmBaseConfig,          // Contains basic TPM configuration
    pub dim_mode: String,                 // DIM mode
    pub dim_path: Option<String>,         // DIM path
    pub cache_dir: Option<String>,        // Cache directory
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "attester_type")]
pub enum PluginParams {
    #[serde(rename = "tpm_boot")]
    TpmBoot(TpmConfig),
    #[serde(rename = "tpm_ima")]
    TpmIma(ImaConfig),
    #[serde(rename = "tpm_dim")]
    TpmDim(DimConfig),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PluginConfig {
    pub name: String,
    pub policy_id: Vec<String>,
    pub path: String,
    pub enabled: bool,
    pub params: Option<PluginParams>,
}

// Initial Random Delay Configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InitialDelayConfig {
    pub min_seconds: u64,  // Minimum delay in seconds
    pub max_seconds: u64,  // Maximum delay in seconds
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SchedulerConfig {
    pub name: String, // challenge...
    pub retry_enabled: bool, // Whether to retry the task
    pub cron_expression: String, // For example, "0 */6 * * *" to run every 6 hours
    pub initial_delay: Option<InitialDelayConfig>, // Optional startup delay configuration
    pub max_retries: Option<usize>, // Optional maximum retries
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    pub ca_path: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerConfig {
    pub server_url: String,
    pub tls: Option<TlsConfig>,  // Optional TLS configuration, tls must be set if server_url start with 'https'.
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentConfig {
    pub listen_address: String,
    pub listen_port: u16,
    pub uuid: Option<String>,  // Optional UUID to uniquely identify the agent
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LoggingConfig {
    pub level: String,
    pub file: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub agent: AgentConfig,
    pub server: ServerConfig,
    pub plugins: Vec<PluginConfig>,
    pub schedulers: Vec<SchedulerConfig>,
    pub logging: LoggingConfig,
}

/// Configuration manager that handles loading and accessing configuration settings
///
/// The configuration file is loaded using the following priority order:
/// 1. Command line specified path (if provided and the file exists)
/// 2. Current working directory: ./agent_config.yaml
/// 3. System-wide configuration: /etc/attestation_agent/agent_config.yaml
///
/// If no configuration file is found in any of these locations, an error is returned.
pub static AGENT_CONFIG: ConfigSingleton<Config> = ConfigSingleton::new();

#[derive(Clone)]
pub struct ConfigManager {
    config_path: String, // Records the actual configuration file path used
}

impl ConfigManager {
    pub fn new(config_path: &str) -> Result<Self, Box<dyn std::error::Error>> {

        let actual_path = Self::find_config_path(config_path)?;

        AGENT_CONFIG.initialize(&actual_path)
            .map_err(|e| format!("Failed to initialize config: {}", e))?;

        Ok(Self {
            config_path: actual_path,
        })
    }

    fn find_config_path(cli_path: &str) -> Result<String, Box<dyn std::error::Error>> {
        // 1. Check command line specified path
        if !cli_path.is_empty() {
            let path = PathBuf::from(cli_path);
            if path.exists() {
                return Ok(cli_path.to_string());
            }
        }
        
        // 2. Check current working directory
        let current_dir_config = PathBuf::from("agent_config.yaml");
        if current_dir_config.exists() {
            return Ok(current_dir_config.to_string_lossy().to_string());
        }
        
        // 3. Check system-wide configuration directory
        let etc_config = PathBuf::from("/etc/attestation_agent/agent_config.yaml");
        if etc_config.exists() {
            return Ok(etc_config.to_string_lossy().to_string());
        }

        Err("Could not find configuration file. Tried command line path, current directory, and /etc directory.".into())
    }

    /// Get the actual path of the configuration file
    pub fn get_config_path(&self) -> &str {
        &self.config_path
    }

    /// Serialize any value that implements Serialize to JSON string
    pub fn to_json<T: serde::Serialize>(value: &T) -> Result<String, String> {
        serde_json::to_string(value)
            .map_err(|e| format!("Failed to serialize to JSON: {}", e))
    }
}