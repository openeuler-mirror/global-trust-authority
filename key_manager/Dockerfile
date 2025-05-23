# 构建阶段
# 使用rust完整版镜像，生产环境推荐使用轻量级镜像 rust:1.85.0-slim
FROM rust:1.85 AS builder

# 配置 Rust 国内镜像源
ENV CARGO_HOME=/usr/local/cargo
RUN echo '[source.crates-io]' > $CARGO_HOME/config \
    && echo 'replace-with = "ustc"' >> $CARGO_HOME/config \
    && echo '[source.ustc]' >> $CARGO_HOME/config \
    && echo 'registry = "sparse+https://mirrors.ustc.edu.cn/crates.io-index/"' >> $CARGO_HOME/config

RUN sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources \
    && sed -i 's/security.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources

RUN apt update && \
    apt install -y apt-utils && \
    apt install -y cmake

# 安装构建依赖 pkg-config 处理c库   libssl-dev处理OpenSSL
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

# 设置环境变量（独立的 ENV 指令）
ENV PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig

# 创建工作目录
WORKDIR /var/key_manager/app

# 复制所有源码
COPY . .

# 构建指定包
RUN cargo build --release --package key_managerd

# 运行时阶段：-----------------------------
# 使用轻量级基础镜像
FROM debian:bookworm-slim

# 替换阿里云镜像（适用于 Debian Bookworm）
RUN sed -i 's/deb.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources \
    && sed -i 's/security.debian.org/mirrors.aliyun.com/g' /etc/apt/sources.list.d/debian.sources

RUN mkdir /opt/key_manager
RUN mkdir /opt/key_manager/deps
RUN mkdir /opt/key_manager/script

# 从构建阶段复制可执行
COPY --from=builder /var/key_manager/app/target/release/key_managerd /opt/key_manager
COPY --from=builder /var/key_manager/app/target/release/key_manager /opt/key_manager
COPY --from=builder /var/key_manager/app/.env /opt/key_manager
COPY --from=builder /var/key_manager/app/deps/* /opt/key_manager/deps/
COPY --from=builder /var/key_manager/app/script/* /opt/key_manager/script/
COPY --from=builder /var/key_manager/app/certs/* /tmp/certs/
RUN chmod -R +x /opt/key_manager/*

# 安装运行时依赖  libssl3 OpenSSL 运行时库
RUN apt-get update && apt-get install -y \
    libssl3 \
    zlib1g \
    libcurl4 \
    procps \
    && rm -rf /var/lib/apt/lists/*

# 安装 openssl
RUN apt-get update && \
    apt-get install -y openssl && \
    rm -rf /var/lib/apt/lists/*

# 安裝openbao
RUN apt-get update && apt-get install bao || apt-get install -f -y

EXPOSE 8082

# 设置入口点
ENTRYPOINT ["/opt/key_manager/deps/openbao_init.sh"]