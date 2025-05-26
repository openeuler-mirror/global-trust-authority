# Attestation Common Development Process and Feature Usage Guide

## 1. Feature Introduction
Attestation Common is a shared code library for the remote attestation system, providing shared functionality for both Agent and Service, including:
- Data structure definitions
- Error handling
- Encryption tools
- Common utility functions
- Middleware components, etc.

## 2. Development Environment Configuration

### 2.1 Required Components
- Rust 1.82 or higher

## 3. Project Structure Description

### 3.1 Directory Structure
```plaintext
attestation_common/
├── cache/           # Cache management
├── distributed_lock/# Distributed lock
├── common_log/      # Security logging
├── mq/             # Message queue
├── rdb/            # Relational database
├── config_manager/ # Configuration management
├── env_config_parse/# Environment configuration parsing
├── jwt/            # JWT handling
├── ratelimit/      # Rate limiting
├── schedule_job/   # Scheduled jobs
```

## 4. Development Process Guide

### 4.1 Adding New Feature Flow
- 1 Define Data Model
  // src/models/entity.rs
  #[derive(Debug, Serialize, Deserialize)]
  pub struct Entity  {
  pub name: String,
  }

- 2 Implement Error Handling
  // src/error/types/entity_error.rs
  #[derive(Debug, Error)]
  pub enum EntityError {
  #[error("Invalid name: {0}")]
  InvalidNonce(String),
  #[error("Entity expired")]
  Expired,
  }

- 3 Add Utility Functions
  // src/utils/entity_utils.rs
  pub fn is_name_valid(name: String) -> bool {

}

### 3.2 Usage Examples

- 1 Encryption Tool Usage
  // Generate hash value
  let hash = crypto::hash::generate_hash(data)?;

// Key management
let key_pair = crypto::keys::generate_key_pair()?;

- 2 Rate Limit Usage
  let governor = create_rate_limiter(
  requests_per_second,
  burst_size
  )?;

## 5. Feature Usage Guide

### 5.1 Encryption Functionality
// Hash calculation
use attestation_common::crypto::hash;
let hash_value = hash::sha256(data);

// Key operations
use attestation_common::crypto::keys;
let key_pair = keys::generate_rsa_key_pair(2048)?;

### 5.2 Error Handling
// Configure rate limit
use attestation_common::error::{Result, Error};

fn process_data() -> Result<()> {
// Processing logic
Ok(())
}


### 5.3 Rate Limiting
use attestation_common::ratelimit::RateLimiter;

let limiter = RateLimiter::new(10, 5)?; // 10 req/s, burst 5

## 6. Testing Guide

### 6.1 Unit Testing（tests/）
#[cfg(test)]
mod tests {
use super::*;

    #[test]
    fn test_hash_generation() {
        // code implementation
    }
}

## 7. Build
- Build：cargo build