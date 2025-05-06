# Build stage
# Using complete rust image, production environment recommends using lightweight image rust:1.85.0-slim
FROM rust:1.85 AS builder

# Configure Rust mirror source in China
ENV CARGO_HOME=/usr/local/cargo
RUN echo '[source.crates-io]' > $CARGO_HOME/config.toml \
    && echo 'replace-with = "ustc"' >> $CARGO_HOME/config.toml \
    && echo '[source.ustc]' >> $CARGO_HOME/config.toml \
    && echo 'registry = "sparse+https://mirrors.ustc.edu.cn/crates.io-index/"' >> $CARGO_HOME/config.toml

RUN sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources \
    && sed -i 's/security.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources

RUN apt update && \
    apt install -y apt-utils

# Install build dependencies: pkg-config for C libraries, libssl-dev for OpenSSL
RUN apt-get update && apt-get install -y \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /var/test_docker/app

# Copy all source code (this will overwrite dummy files)
COPY Cargo.toml Cargo.lock ./
COPY key_manager ./key_manager
COPY certs ./certs

RUN sed -i '/members = \[/,/\]/ {/attestation_*/d}' Cargo.toml
RUN sed -i '/members = \[/,/\]/ {/plugin_manager/d}' Cargo.toml

WORKDIR /var/test_docker/app/key_manager

# Copy rust standard library files to build directory
RUN cargo build --release --package key_managerd --target-dir ./target

# Runtime stage: -----------------------------
# Use lightweight base image
FROM debian:bookworm-slim

# Replace with Aliyun mirror (for Debian Bookworm)
RUN sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources \
    && sed -i 's/security.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources

RUN mkdir /opt/key_manager
RUN mkdir /opt/key_manager/deps
RUN mkdir /opt/key_manager/script

# Copy executables from build stage
COPY --from=builder /var/test_docker/app/key_manager/target/release/key_managerd /opt/key_manager
COPY --from=builder /var/test_docker/app/key_manager/target/release/key_manager /opt/key_manager
COPY --from=builder /var/test_docker/app/key_manager/.env /opt/key_manager
COPY --from=builder /var/test_docker/app/key_manager/deps/* /opt/key_manager/deps/
COPY --from=builder /var/test_docker/app/key_manager/script/* /opt/key_manager/script/
COPY --from=builder /var/test_docker/app/certs/* /tmp/certs/
RUN chmod -R +x /opt/key_manager/*

# Install runtime dependencies libssl3 OpenSSL runtime library
RUN apt-get update && apt-get install -y \
    libssl3 \
    wget \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Install openssl
RUN apt-get update && \
    apt-get install -y openssl && \
    rm -rf /var/lib/apt/lists/*

ARG TARGETARCH
ARG OPENBAO_VERSION="2.2.0"
ENV DOWNLOAD_ARCH="${TARGETARCH}"
# Install openbao
RUN cd /opt/key_manager/deps &&  wget -q "https://github.com/openbao/openbao/releases/download/v${OPENBAO_VERSION}/bao_${OPENBAO_VERSION}_linux_${DOWNLOAD_ARCH}.deb" && \dpkg -i ./bao_*_linux_*.deb
# RUN cd /opt/key_manager/deps && \dpkg -i ./bao_*_linux_*.deb

EXPOSE 8082

# Set entry point
ENTRYPOINT ["/opt/key_manager/deps/openbao_init.sh"]