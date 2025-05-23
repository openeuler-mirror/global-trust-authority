# Build stage
# Using complete rust image, production environment recommends using lightweight image rust:1.85.0-slim
FROM rust:1.85 AS builder

# Configure Rust mirror source in China
ENV CARGO_HOME=/usr/local/cargo
RUN echo '[source.crates-io]' > $CARGO_HOME/config \
    && echo 'replace-with = "ustc"' >> $CARGO_HOME/config \
    && echo '[source.ustc]' >> $CARGO_HOME/config \
    && echo 'registry = "sparse+https://mirrors.ustc.edu.cn/crates.io-index/"' >> $CARGO_HOME/config

RUN sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources \
    && sed -i 's/security.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources

# Install build dependencies: pkg-config for C libraries, libssl-dev for OpenSSL
RUN apt-get update && apt-get install -y \
    pkg-config \
    zlib1g-dev \
    libssl-dev \
    git \
    cmake \
    make \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch v2.3.0 https://gitee.com/mirrors/librdkafka.git && \
    cd librdkafka && \
    ./configure --prefix=/usr --libdir=/usr/lib/x86_64-linux-gnu && \
    make && \
    make install && \
    ldconfig

# Set environment variables (independent ENV instruction)
ENV PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig

# Create working directory
WORKDIR /var/test_docker/app

# Only copy dependency-related files (utilizing Docker cache layers)
COPY Cargo.toml .
COPY Cargo.lock .
COPY attestation_service/attestation_service/Cargo.toml ./attestation_service/attestation_service/Cargo.toml
COPY attestation_service/service_restful/Cargo.toml ./attestation_service/service_restful/Cargo.toml
COPY attestation_service/policy/Cargo.toml ./attestation_service/policy/Cargo.toml
COPY attestation_service/rv/Cargo.toml ./attestation_service/rv/Cargo.toml
COPY attestation_service/endorserment/Cargo.toml ./attestation_service/endorserment/Cargo.toml
COPY attestation_service/nonce/Cargo.toml ./attestation_service/nonce/Cargo.toml
COPY attestation_service/token_management/Cargo.toml ./attestation_service/token_management/Cargo.toml
COPY attestation_service/policy_engine/Cargo.toml ./attestation_service/policy_engine/Cargo.toml
COPY attestation_service/key_management/Cargo.toml ./attestation_service/key_management/Cargo.toml
COPY attestation_service/attestation/Cargo.toml ./attestation_service/attestation/Cargo.toml
COPY attestation_service/resource_provider/Cargo.toml ./attestation_service/resource_provider/Cargo.toml
COPY attestation_service/server_config/Cargo.toml ./attestation_service/server_config/Cargo.toml
COPY attestation_service/verifier/tpm/common/Cargo.toml ./attestation_service/verifier/tpm/common/Cargo.toml
COPY attestation_service/verifier/tpm/boot/Cargo.toml ./attestation_service/verifier/tpm/boot/Cargo.toml
COPY attestation_service/verifier/tpm/ima/Cargo.toml ./attestation_service/verifier/tpm/ima/Cargo.toml
COPY plugin_manager/Cargo.toml ./plugin_manager/Cargo.toml
COPY attestation_common/cache/Cargo.toml ./attestation_common/cache/Cargo.toml
COPY attestation_common/config_manager/Cargo.toml ./attestation_common/config_manager/Cargo.toml
COPY attestation_common/distributed_lock/Cargo.toml ./attestation_common/distributed_lock/Cargo.toml
COPY attestation_common/env_config_parse/Cargo.toml ./attestation_common/env_config_parse/Cargo.toml
COPY attestation_common/common_log/Cargo.toml ./attestation_common/common_log/Cargo.toml
COPY attestation_common/mq/Cargo.toml ./attestation_common/mq/Cargo.toml
COPY attestation_common/ratelimit/Cargo.toml ./attestation_common/ratelimit/Cargo.toml
COPY attestation_common/rdb/Cargo.toml ./attestation_common/rdb/Cargo.toml
COPY attestation_common/schedule_job/Cargo.toml ./attestation_common/schedule_job/Cargo.toml
COPY attestation_common/jwt/Cargo.toml ./attestation_common/jwt/Cargo.toml

# Create a dummy lib.rs to download dependencies early
RUN mkdir -p attestation_service/src && echo 'fn main() {}' > attestation_service/src/lib.rs

# Exclude agent and attestation_cli interference
RUN sed -i '/members = \[/,/\]/ {/attestation_agent/d}' Cargo.toml
RUN sed -i '/members = \[/,/\]/ {/attestation_cli/d}' Cargo.toml
RUN sed -i '/members = \[/,/\]/ {/key_manager/d}' Cargo.toml

# Download dependencies (keep in cache)
RUN cargo fetch

# Copy all source code (this will overwrite dummy files)
COPY . .

# Remove attestation_service unrelated directories
RUN rm -rf attestation_agent
RUN rm -rf attestation_cli
RUN rm -rf .cargo

# Exclude agent interference
RUN sed -i '/members = \[/,/\]/ {/attestation_agent/d}' Cargo.toml
RUN sed -i '/members = \[/,/\]/ {/attestation_cli/d}' Cargo.toml
RUN sed -i '/members = \[/,/\]/ {/key_manager/d}' Cargo.toml

# Build specific packages
RUN cargo build --release --package attestation_service --features docker_build
RUN cargo build --release --package tpm_boot_verifier
RUN cargo build --release --package tpm_ima_verifier

# Copy rust standard library files to build directory
RUN cp $(find $(rustc --print sysroot) -name "libstd-*.so") /var/test_docker/app/target/release/

# Runtime stage: -----------------------------
# Use lightweight base image
FROM debian:bookworm-slim

# Replace with Aliyun mirror (for Debian Bookworm)
RUN sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources \
    && sed -i 's/security.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources

# Install runtime dependencies libssl3 OpenSSL runtime library
RUN apt-get update && apt-get install -y \
    libssl3 \
    zlib1g \
    libcurl4 \
    && rm -rf /var/lib/apt/lists/*

# Copy executables from build stage
COPY --from=builder /usr/lib/x86_64-linux-gnu/*kafka* /usr/lib/x86_64-linux-gnu/
RUN ldconfig
COPY --from=builder /var/test_docker/app/target/release/attestation_service /usr/local/bin/

## Copy configuration files
#COPY logging.yaml /var/test_docker/app/logging.yaml
#COPY server_config.yaml /var/test_docker/app/server_config.yaml
#RUN chmod 644 /var/test_docker/app/*.yaml

# Install openssl
RUN apt-get update && \
    apt-get install -y openssl && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/attestation_server/certs && \
    openssl req -x509 -newkey rsa:4096 -nodes \
        -keyout /etc/attestation_server/certs/key.pem \
        -out /etc/attestation_server/certs/cert.pem \
        -days 365 \
        -subj "/CN=127.0.0.1"
COPY certs/* /etc/attestation_server/certs/
# Copy dynamic libraries
COPY --from=builder /var/test_docker/app/target/release/*.so /usr/local/lib/

# Configure dynamic library path
ENV LD_LIBRARY_PATH=/usr/local/lib

# Set entry point
ENTRYPOINT ["attestation_service"]
