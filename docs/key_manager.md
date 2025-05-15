# Key Manager
## 简介
Key Manager 是一个基于第三方KMS(OpenBao)的密钥分发服务，旨在简化远程证明（Remote Attestation）过程中所需的密钥管理流程。该项目通过集中化管理 attestation_service 所依赖的各类密钥（如身份密钥、会话密钥等），提供高效的密钥查询、导入及生命周期管理功能，确保密钥的安全存储与合规使用。

核心功能：
* 密钥统一管理：支持对远程证明流程中涉及的密钥进行集中化存储与分类。
* 密钥查询：提供灵活的查询接口，快速检索密钥信息。
* 密钥导入：支持多种格式密钥的安全导入与验证，确保数据完整性。
* 与 OpenBao 集成：无缝对接 OpenBao，强化密钥管理的安全性与可审计性。

应用场景：
适用于需要高安全级别的远程证明场景，如机密计算（Confidential Computing）、TEE（可信执行环境）等，帮助开发者降低密钥管理的复杂度，提升整体系统的可信性。
## 部署步骤
当前Key Manager支持RPM和Docker两种部署方式，用户需要从源码进行编译，获取安装包。
### 前置条件
#### 1.环境安装
* rust环境
```shell
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```
* openssl环境
```shell
dnf install openssl openssl-devel #Linux (RHEL/CentOS/Fedora)
apt update && apt install openssl libssl-dev #Linux (Debian/Ubuntu)
```
#### 2.生成测试证书(可选)
当前Key Manager使用MTLS双向认证进行通信，因此需要进行对应的证书配置。
使用当前路径下如下脚本进行MTLS证书生成：
```shell
# 当前部署服务器的IP用于证书SAN字段
bash script/test_certificate_generation.sh -p <指定路径> -i <当前部署服务器的IP>
```
当前的证书会影响后续docker的安装，建议放置到当前global-trust-authority/certs目录下。
#### 3.openbao部署
根据系统下载对应版本(当前对应openbao版本为v2.2.0)
```shell
# Ubuntu/Debian amd64
wget -q "https://github.com/openbao/openbao/releases/download/v2.2.0/bao_2.2.0_linux_amd64.deb"

# CentOS/RHEL amd64
wget -q "https://github.com/openbao/openbao/releases/download/v2.2.0/bao_2.2.0_linux_amd64.rpm"

# Ubuntu/Debian arm64
wget -q "https://github.com/openbao/openbao/releases/download/v2.2.0/bao_2.2.0_linux_arm64.deb"

# CentOS/RHEL arm64
wget -q "https://github.com/openbao/openbao/releases/download/v2.2.0/bao_2.2.0_linux_arm64.rpm"
```
使用以下命令安装openbao
```shell
# Ubuntu/Debian
dpkg -i bao_2.2.0_linux_amd64.deb
# CentOS/RHEL
rpm -ivh --nodeps bao_2.2.0_linux_amd64.rpm
```
修改当前openbao的配置文件，位于/etc/openbao/openbao.hcl路径。
修改为如下配置：
```hcl
ui = true
storage "file" {
  path = "/opt/openbao/data"
}

# HTTP listener
listener "tcp" {
  address = "127.0.0.1:8200"
  tls_disable = 1
}
```
使用如下命令启动当前openbao
```shell
systemctl start openbao.service
```
导入环境变量
```shell
export BAO_ADDR=http://127.0.0.1:8200/
```
执行openbao初始化命令
```shell
bao operator init
```
得到部分结果如下：
```text
Unseal Key 1: DYd304ycrZXtzCool+2MNaEo3r/XAu4YjgBj04UiXN/+
Unseal Key 2: D8LNBo/76HRPKl/AMjLCkvCFLl23BenURZec7ov+szjW
Unseal Key 3: qXkzqd9NlemvMOXeYcqBsEp4b47hYlFZ0H0cxusb/pFj
Unseal Key 4: jhV2JGuuBgkyyWHz7ZQlAq1ov5egGqK7XHO68fQPo5f1
Unseal Key 5: ZVR+AopsEgJ2RnDE3AmtJpPYLkaPSInHicJ/ZPzQNzaL

Initial Root Token: s.tNAqbGc4RI9TKVaqwJjsqibP
```
记录下unseal key和root token。
使用以下命令解封openbao
```shell
# 当前unseal key来自于上述控制台打印内容，使用3条即可解封当前openbao
bao operator unseal <unseal key>
```
### RPM安装Key Manager
#### 1.安装依赖
```shell
sudo yum install -y gcc rpm-build openssl-devel
```
#### 2.构建 RPM 包
```shell
# 进入项目根目录，执行以下命令构建rpm包
sh key_manager/script/rpm_build.sh
```
#### 3.安装 RPM
```shell
sudo rpm -ivh ~/rpmbuild/RPMS/aarch64/global-trust-authority-key-manager-0.1.0-1.aarch64.rpm
```
#### 4.启动Key Manager
当前rpm会安装到/usr/local/key_manager/bin目录下，修改当前路径下的配置文件
```shell
vim /usr/local/key_manager/bin/.env
# 需修改的配置文件如下
ROOT_CA_CERT_PATH=  # MTLS证书中根CA证书的路径
KEY_MANAGER_CERT_FILE_PATH= # 当前根CA签发出来的key Manager的证书
KEY_MANAGER_KEY_FILE_PATH= # 当前根CA签发出来的key Manager的私钥
KEY_MANAGER_ROOT_TOKEN= # 当前openbao访问的root token
KEY_MANAGER_SECRET_ADDR= # 当前openbao访问的地址，默认可填写为http://127.0.0.1:8200/
```
使用后台启动命令启动当前Key Manager即可
```shell
./key_managerd &
```
日志路径可参考当前.env中该配置选项**KEY_MANAGER_LOG_PATH**
### Docker安装
#### 1.安装docker环境
```shell
# Ubuntu/Debian
sudo apt update
sudo apt install -y apt-transport-https ca-certificates curl gnupg lsb-release

# CentOS/RHEL
sudo yum install -y yum-utils device-mapper-persistent-data lvm2
```
#### 2.docker打包镜像
当前Key Manager需使用两个docker基础镜像：
```dockerfile
rust:1.85
debian:bookworm-slim
```
当前部署需要使用MTLS双向证书，因此需要把证书放置在global-trust-authority/certs文件夹中。
在当前Key Manager目录下，使用如下命令打包当前Key Manager镜像
```shell
docker compose build key_manager
```
#### 3.启动docker镜像
```shell
docker run -d -p 8082:8082 key_manager:latest
```
## 查询密钥
当前服务对外提供一个RestfulAPI接口供外部查询密钥，接口参数如下：
```text
GET /v1/vault/get_signing_keys
```
在正常启动当前Key Manager之后，可使用如下curl命令测试当前Key Manager是否正常启动，若能正常查询结果，则说明当前Key Manager部署成功
```shell
# ra_client_cert.pem 当前由根CA签发的客户端证书
# ra_client_key.pem 当前由根CA签发的客户端私钥
# km_cert.pem 当前根CA证书
curl  --cert ra_client_cert.pem \ 
      --key  ra_client_key.pem \
      --cacert km_cert.pem \
      --resolve "key_manager:8082:127.0.0.1" \
      https://key_manager:8082/v1/vault/get_signing_keys
```
## 导入密钥
### 前置条件
1. openbao服务安装并正常运行
2. Key Manager已正常启动
### 使用Key Manager命令行工具进行导入
```shell
./key_manager put --key_name <KEY_NAME> --algorithm <ALGORITHM> --encoding <ENCODING> --key_file <KEY_FILE>
```
#### 示例
1. 生成密钥文件rsa_3072.key
2. 执行以下命令导入名称为TSK，编码方式为PEM，加密算法为RSA 3072的密钥
```shell
# 进入Key Manager安装bin目录下, 执行以下命令进行导入
./key_manager put --key_name TSK --algorithm rsa_3072 --encoding pem --key_file rsa_3072.key
```
3. 提示以下信息表示导入成功
```shell
success to handle command
```
#### 查看帮助
执行以下命令查看工具帮助信息
```shell
./key_manager put --help
```
## 测试数据生成
使用当前key_manager/script/generate_test_data.sh可生成对应的测试数据。
### rpm部署
拷贝当前脚本到/usr/local/key_manager/bin目录下
```shell
cp key_manager/script/generate_test_data.sh /usr/local/key_manager/bin
```
执行当前测试数据生成脚本，示例如下：
```shell
cd /usr/local/key_manager/bin
# 表示当前给三个类型的私钥预制rsa3072格式的2个版本的数据
bash generate_test_data.sh rsa_3072 2
```
### docker部署
使用以下命令查看当前Key Manager的docker容器ID
```shell 
docker ps
```
进入当前docker的命令行
```shell
docker exec -it <容器ID> /bin/bash
```
进入当前容器部署目录/opt/key_manager，执行当前脚本即可
```shell
cd /opt/key_manager
# 表示当前给三个类型的私钥预制rsa3072格式的2个版本的数据
bash generate_test_data.sh rsa_3072 2
```