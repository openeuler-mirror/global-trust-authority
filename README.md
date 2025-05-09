# HRA (Huawei Remote Attestation)

## Introduction
Unified Remote Attestation is an open-source confidential computing project dedicated to providing a unified architecture for confidential computing and trusted computing remote attestation, promoting the development of confidential computing ecosystem. This project provides a complete remote attestation solution, including client agent and server-side service components.

## Features

### 1. Remote Attestation Challenge Generation and Verification

Remote attestation challenge generation and verification is the core functionality of Unified Remote Attestation. It includes the following steps:
1. Client agent generates remote attestation challenge.
2. Server verifies remote attestation challenge.

## External Interfaces

Please refer to the [API documentation](./docs/hra_api.md) for external interfaces.

## Components

| Directory           | Description          | Detailed Documentation |
| ------------------- | -------------------- | --------------------- |
| attestation_agent   | Remote attestation agent module | [Development Guide](docs/attestation_agent.md) |
| attestation_service | Remote attestation service module | [Development Guide](docs/attestation_service.md) |
| attestation_common  | Common code          | [Development Guide](docs/attestation_common.md) |

## Development

### Environment Requirements

* Processor: Must support Intel SGX (Intel Software Guard Extensions)
* Operating System:
  - Windows 10/11 (Development Environment)
  - openEuler 21.03 or higher (Production Environment)
  - openEuler 20.03 LTS SP2 or higher (Production Environment)

### Dependencies

* Rust 1.70.0 or higher
* PostgreSQL 14.0 or higher
* OpenSSL development library
* libssl-dev (for OpenSSL)
* pkg-config

Windows environment dependency installation:
```bash
winget install Rust.Rust
winget install PostgreSQL.PostgreSQL
winget install OpenSSL
```

### Build

```
# Full build
cargo clean
cargo build
# Build specific package
cargo build -p *
# Run specific package
cargo run -p *
# Build and run tests
cargo test
# Build and run specific package tests
cargo test -p *
# Build and run specific test case
cargo test * -p *
# Build release version
cargo build --release
```

## Usage Guide

### Clone Code
git clone https://gitee.com/openeuler/global-trust-authority.git
cd global-trust-authority

### Build Project
cargo build --release

### Run Project
- Run server
  cargo run -p attestation_service
- Run client
  cargo run -p attestation_agent

## Contribution Guide
- Fork this repository
- Create a feature branch ( git checkout -b feature/AmazingFeature )
- Commit your changes ( git commit -m 'Add some AmazingFeature' )
- Push to the branch ( git push origin feature/AmazingFeature )
- Create Pull Reques

## License
This project is licensed under Mulan PSL v2

## Contact
- Project URL: https://gitee.com/openeuler/global-trust-authority
- Issue Tracker: https://gitee.com/openeuler/global-trust-authority/issues