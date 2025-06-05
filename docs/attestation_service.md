# Attestation Service Development Process and Feature Usage Guide

## 1. Feature Introduction
Attestation Service is the server-side component of the remote attestation system, providing the following main functions:
- Remote attestation challenge generation and verification
- Policy management and verification
- Certificate management
- Key management

## 2. Development Environment Configuration

### 2.1 Required Components
- Rust 1.82 or higher
- Mysql 8.0.4/PostgreSQL 14.0 or higher
- Redis 6.2 or higher
- Kafka 3.8 or higher
- OpenSSL development library
- libssl-dev (for OpenSSL)
- pkg-config

## 3. Directory Structure
```plaintext
attestation_service/
├── attestation/        # Core attestation functionality
├── attestation_service/# Main attestation service implementation
├── endorserment/      # Certificate management
├── key_management/    # Key management
├── nonce/            # Random number generation and management
├── policy/           # Policy definition and management
├── policy_engine/    # Policy engine implementation
├── resource_provider/ # Resource provider
├── rv/               # Remote verification related
├── server_config/    # Server configuration
├── token_management/ # Token management
├── verifier/         # Verifier implementation
```

## 4. Development Process Guide

### 4.1 Add New Feature Flow
- 1 Define Entity（entities/）
```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct Entity  {
  pub name: String,
}
```

- 2 Implement Data Access Layer（repositories/）
```rust
pub async fn save_entity(pool: &PgPool, entity: &Entity) -> Result<(), Error> {
  sqlx::query!(
  "INSERT INTO entity (name) VALUES ($1)",
  entity.name
  )
  .execute(pool)
  .await?;
  Ok(())
}
```

- 3 Implement Business Logic（services/）
```rust
pub async fn process_entity(request: EntityRequest) -> Result<EntityResponse, ServiceError> {
  // Business logic implementation
}

```

- 4 Add Controller（controllers/）
```rust
pub async fn create_entity(
  State(pool): State<PgPool>,
  Json(request): Json<EntityRequest>,
) -> Result<Json<EntityResponse>, ServiceError> {
  let entity = process_entity(request).await?;
  Ok(Json(entity))
}
```

- 5 Configure Routes（routes/）
```rust
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
  cfg.service(
    web::scope("/api")
            .route("/entity", web::post().to(create_entity))
  );
}
```

## 5. Feature Usage Guide

### 5.1 Database Operation
```rust
// Create connection pool
let pool = PgPoolOptions::new()
.max_connections(5)
.connect(&database_url)
.await?;

// Execute query
let result = sqlx::query!("SELECT * FROM entity ")
.fetch_all(&pool)
.await?;
```


### 5.2 Rate Limiting
```rust
// Execute query
let governor = Arc::new(Governor::new(&GovernorConfigBuilder::default()
.requests_per_second(10)
.burst_size(5)
.finish()
.unwrap()));
```

### 5.3 Logging
```rust
// Configure logging
log::info!("Processing request: {:?}", request);
log::error!("Error occurred: {:?}", error);
```

## 6. Testing Guide

### 6.1 Unit Testing（tests/）
```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_entity_validation() {
        // Test implementation
    }
}
```

## 7. Deployment Guide

Refer to GTA_Usage_Guidelines.md for more details