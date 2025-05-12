# 【远程证明】构建及运行环境安装
## 1. 构建依赖
### 1.1. Rust
```bash
# 官网安装方式
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 使用国内源进行安装（推荐）
# RUSTUP_UPDATE_ROOT：指定 rust-init 的下载地址
export RUSTUP_UPDATE_ROOT=https://mirrors.ustc.edu.cn/rust-static/rustup
# RUSTUP_DIST_SERVER：指定 rust 配套组件的下载地址
export RUSTUP_DIST_SERVER=https://mirrors.tuna.tsinghua.edu.cn/rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
## 2. 运行依赖
### 2.1. Redis
```bash
# OpenEuler rpm包安装
# 添加源
dnf config-manager --add-repo https://repo.openeuler.org/openEuler-22.03-LTS-SP3/everything/aarch64
# 更新源索引
dnf clean all && dnf makecache
# 安装Redis软件包
dnf install redis
# 修改配置文件
vi /etc/redis/redis.conf
# 注释掉，可以进行远程连接
bind 127.0.0.1 ::1 -> # bind 127.0.0.1 ::1
# 新增一行
bind 0.0.0.0
# 启动Redis服务
sudo systemctl start redis
# 开机自启
sudo systemctl enable redis
# 查看Redis服务运行状态
sudo systemctl status redis
# 停止Redis服务
sudo systemctl stop redis

# 应用镜像安装  
# 获取应用镜像
docker pull openeuler/redis:7.2.5-oe2203sp3
# 启动容器
docker run -d --name my-redis -p 6379:6379 openeuler/redis:7.2.5-oe2203sp3
# 查看运行日志
docker logs -f my-redis
# 设用shell交互
docker exec -it my-redis /bin/bash

# 测试访问
redis-cli -h 127.0.0.1 -p 6379
```
运行环境需要保证Redis运行端口可访问，如果是云服务器，需要在后台进行开启，如果是本地机器需要查看防火墙设置是否对所需端口进行拦截。
[安装参考链接](https://easysoftware.openeuler.org/zh/field/detail?type=IMAGE&appPkgId=redisopenEuler-22.03-LTS-SP37.2.5-oe2203sp3aarch64&rpmPkgId=openEuler-22.03-LTS-SP3everythingaarch64redis4.0.14-6.oe2203sp3aarch64)
### 2.2. MySQL
```bash
# OpenEuler rpm包安装
# 添加源
dnf config-manager --add-repo https://archives.openeuler.openatom.cn/openEuler-22.09/OS/x86_64
# 更新索引
dnf clean all && dnf makecache
# 安装MySQL软件包
dnf install mysql
# 配置文件（默认不需要修改）
/etc/mysql/mysql.conf.d/mysqld.cnf
# 启动mysql服务
sudo systemctl start mysqld
# 开机自启
sudo systemctl enable mysqld
# 查看mysql服务运行状态
sudo systemctl status mysqld
# 停止mysql服务
sudo systemctl stop mysqld

# 首次登录
# 默认root用户是没有密码的
sudo mysql -u root -p
# 进入mysql命令行界面后，创建新用户和数据库
CREATE USER 'username'@'localhost' IDENTIFIED   BY 'password';
CREATE DATABASE database_name;
GRANT ALL PRIVILENGES ON database_name.* TO 'username'@'localhost';
FLUSH PRIVILEGES;

# 测试访问
# 使用Dbeaver连接远程mysql服务器
# 驱动属性设置
allowPublicKeyRetrieval true
```

### 2.3. OpenSSL依赖

```bash
# 安装 OpenSSL 开发库
# 在 Ubuntu 或 Debian 系统上，可以使用 apt 包管理器安装 OpenSSL 开发库：
sudo apt update
sudo apt install libssl-dev

# 验证安装
# 如果安装成功，会显示 OpenSSL 的版本号，例如：
# OpenSSL 1.1.1f  31 Mar 2020
openssl version
```
### tpm2-tss安装

```
sudo dnf install tpm2-tss
```

### 2.4 c库依赖
```bash
# 安装GCC
apt update
apt install gcc
```

## 3. 运行项目

### 3.1 下载远程证明
```bash
# clone 代码仓
git clone https://gitee.com/openeuler/global-trust-authority.git

# 进入项目目录
cd ./global-trust-authority

# 构建项目
cargo clean & cargo build
```

### 3.2 下载mock服务
```bash
# clone 代码仓
git clone https://gitee.com/stephen-oriental/attestation_mock.git

# 进入项目目录
cd ./attestation_mock

# 构建项目
cargo clean & cargo build
``` 

### 3.3 运行

注意先后顺序，必须先运行mock服务，否则global-trust-authority服务无法启动
```bash
# 先进入mock代码目录(attestation_mock),执行
cargo run

# mock运行起来之后，在进入远程证明代码目录（global-trust-authority），执行
cargo run
```
