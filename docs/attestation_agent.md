# Attestation Agent Development Process and Feature Usage Guide

## 1. Feature Introduction
Attestation Agent is the client component of the remote attestation system, providing the following functions:
- Network element evidence collection (TPM PCR, boot information, IMA logs, etc.)
- Remote attestation periodic challenge response
- Attestation token management
- Communication with Attestation Service

## 2. Development Environment Setup

### 2.1 Required Components
- Rust 1.70.0 or higher
- OpenSSL development library
- libssl-dev (for OpenSSL)
- libtss2-dev (for TPM 2.0 access)
- pkg-config

### 2.2 Environment Configuration

- Install required components
```sh
apt-get install -y build-essential pkg-config libssl-dev libtss2-dev
```

- Install Rust
```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

- Configure Rust toolchain
```sh
rustup default stable
rustup component add rustfmt clippy
```

## 3. Directory Structure
```plaintext
attestation_agent/
├── agent               # agent main process, provides service entry
├── agent_restful       # RESTful API implementation, handles evidence collection and token requests
├── attester           # Evidence collection plugin module
│   └── tpm            # TPM related plugins
│       ├── boot       # TPM boot information collection plugin
│       ├── common     # TPM plugin shared code
│       └── ima        # TPM IMA log collection plugin
├── challenge          # Challenge request processing module
├── config             # Configuration management module, handles config file parsing
└── utils              # Common utility module, including network, logging, etc.
```

## 4 Development Process Guide

### 4.1 Adding New Plugin Process

- 1 Implement AgentPlugin trait in the plugin interface
```rust
  pub trait AgentPlugin {
    fn plugin_type(&self) -> &str;
    fn collect_evidence(&self, node_id: Option<&str>, nonce: Option<&[u8]>) 
        -> Result<serde_json::Value, PluginError>;
  }
```

- 2 Create plugin configuration structure
```rust
  #[derive(Debug, Clone, Deserialize)]
  pub struct MyPluginConfig {
      pub enabled: bool,
      pub parameters: HashMap<String, String>,
  }
```

- 3 Implement plugin logic
```rust
  pub struct MyPlugin {
      config: MyPluginConfig,
  }

  impl AgentPlugin for MyPlugin {
      fn plugin_type(&self) -> &str {
          "my_plugin_type"
      }
      
      fn collect_evidence(&self, node_id: Option<&str>, nonce: Option<&[u8]>) 
          -> Result<serde_json::Value, PluginError> {
          // Implement evidence collection logic
      }
  }
```

### 4.2 Implementing Scheduled Task Addition
```rust
    let scheduler_config = SchedulerConfig::new()

    let task = Box::new(move || {
        Box::pin(async move {
            info!("Scheduler task executed");
            Ok(())
        }) as Pin<Box<dyn Future<Output = Result<(), agent_utils::AgentError>> + Send>>
    });

    let mut schedulers = SchedulerBuilders::new();
    schedulers.add(scheduler_config, task);
```

### 4.3 Adding RESTful Interface Routes
```rust
    // start server
    info!("Starting server at listen address: {}:{}", config.agent.listen_address, config.agent.listen_port);
    let rest_config = ServiceConfig::new()
        .with_port(config.agent.listen_port)
        .with_bind_address(&config.agent.listen_address);

    let service = RestService::configure(rest_config)?;

    service.register(
        Method::POST,
        "/rest/global-trust-authority/agent/v1/xxx",
        |_: HttpRequest, body: Option<Value>| foo(body),
    )?;

    service.start_server().await?;
```

## 5 Feature Usage Guide

### 5.1 Scheduled Challenge Task
Configure the challenge scheduled task in the agent_config.yaml's scheduler module. Settings can be modified as needed, such as timing intervals.To prevent server concurrent overload leading to request failures, delay staggering is provided with configurable delay times.

```yaml
    - name: "challenge"                  # Task name
    retry_enabled: true                # Enable retry
    cron_expression: "*/10 * * * * *"  # Execute every 10 seconds
    initial_delay:                     # Random initial delay configuration
      min_seconds: 1                   # Minimum delay 1 second
      max_seconds: 60                  # Maximum delay 60 seconds
    max_retries: 1
```

### 5.2 Token Management
```json
curl -X POST http://localhost:8080/rest/global-trust-authority/agent/v1/tokens -d '{
    "attester_info": [
      {
        "attester_type": "tpm_boot",
        "policy_ids": ["policy1", "policy2"]
      }
    ],
    "challenge": true,
    "attester_data": "test_data"
}'
```

### 5.3 Getting Evidence
```json
curl -X POST http://localhost:8080/rest/global-trust-authority/agent/v1/evidences \
  -H "Content-Type: application/json" \
  -d '{
    "attester_types": ["tpm_boot", "tpm_ima"],
    "nonce_type": "default",
    "nonce": {
      "iat": 123456789,
      "value": "5J7Q3sQbF6Yp6R6T1Qm8k1gX7j9YzvH4l6eQ2J1s8x0a9vT3h2K5z8W0u4x9V7n2b1c6e3w0p8m7u5q9t4r3y2z0v1s6d8a5g",
      "signature": "Y0t2bGxwR1F6dGJmU1l4N3lBUXk2T2JZc3h5T0l6Z3Z4d2lQd2F6R0ZyZ3l6Z2V4V2V5d2F0Y3l6a2N6d2p6d2x5d2V6d2s="
    },
    "attester_data": "custom_data"
  }'
```

### 5.4 Logging
```rust
// Configure logging
log::info!("Processing challenge: {:?}", challenge);
log::error!("Error occurred: {:?}", error);
```

## 6. Testing Guide

### 6.1 Testing Guide（tests/）
```rust
  #[cfg(test)]
  mod tests {
    #[test]
    fn test_evidence_generation() {
    // Test implementation
    }
  }
```

## 7. Deployment Guide

### 7.1 Build and Run
```sh
# Build
cargo build -p attestation_agent

# Run agent
cargo run --bin attestation_agent  ./config/agent_config.yaml
```

### 7.2 Configuration Guide

#### 7.2.1 Configuration File
agent_config.yaml configuration file supports three scenarios:

- Specified file path when starting attestation_agent process
- Same directory as attestation_agent process
- /etc/attestation_agent/agent_config.yaml

#### 7.2.2 Related Configuration Description
- RUST_LOG: Log level (trace, debug, info, warn, error)
- Port: Agent listening port
- Service Address: Remote attestation service address
- TPM Device Access: Usually device