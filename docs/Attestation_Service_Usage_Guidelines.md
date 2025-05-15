# RA-server使用指导

## 拉取代码

```
git clone https://gitee.com/openeuler/global-trust-authority.git
```
![输入图片说明](https://foruda.gitee.com/images/1747300905565880194/51de5334_15438102.png "屏幕截图")

## 修改配置文件

#### .env / .env.rpm

```
vim .env
```

.env文件中配置了远程证明服务在docker容器的相关数据库、中间件、限流等关键配置

![输入图片说明](https://foruda.gitee.com/images/1747300920195255026/2dd8c4bb_15438102.png "屏幕截图")

#### server_config.yaml / server_config_rpm.yaml

server端关于nonce、token、策略、证书、基线的相关配置

|     配置层级     |          字段名称          |          字段含义          | 字段类型 |                        默认值/示例值                         |
| :--------------: | :------------------------: | :------------------------: | :------: | :----------------------------------------------------------: |
|  key_management  |     vault_get_key_url      | 获取签名密钥的Vault服务URL |  string  |     "https://10.10.0.180:8082/v1/vault/get_signing_keys"     |
|  key_management  |      is_require_sign       |        是否要求签名        | boolean  |                             true                             |
| token_management |            jku             |        JWK Set URL         |  string  |                            "jku"                             |
| token_management |            kid             |           密钥ID           |  string  |                            "kid"                             |
| token_management |         exist_time         |     令牌存在时间(毫秒)     | integer  |                            600000                            |
| token_management |            iss             |           签发者           |  string  |                            "iss"                             |
| token_management |        eat_profile         |        EAT配置文件         |  string  |                        "eat_profile"                         |
| token_management |         mq_enabled         |      是否启用消息队列      | boolean  |                            false                             |
| token_management |        token_topic         |        令牌主题名称        |  string  |                       "ra_token_topic"                       |
|      policy      |  export_policy_file.name   |        策略文件名称        | string[] |                   ["tpm_boot", "tpm_ima"]                    |
|      policy      |  export_policy_file.path   |        策略文件路径        | string[] | ["/var/test_docker/app/export_policy/tpm_boot", "/var/test_docker/app/export_policy/tpm_ima"] |
|      policy      | is_verify_policy_signature |      是否验证策略签名      | boolean  |                            false                             |
|      policy      |  single_user_policy_limit  |    单个用户策略限制数量    | integer  |                              30                              |
|      policy      | policy_content_size_limit  |   策略内容大小限制(字节)   | integer  |                             500                              |
|      policy      |  query_user_policy_limit   |    查询用户策略限制数量    | integer  |                              10                              |
|       cert       |   single_user_cert_limit   |    单个用户证书限制数量    | integer  |                              10                              |
|      nonce       |     nonce_valid_period     |     nonce有效周期(秒)      | integer  |                             120                              |
|      nonce       |        nonce_bytes         |       nonce字节长度        | integer  |                              64                              |
|     plugins      |            name            |          插件名称          | string[] |                   ["tpm_boot", "tpm_ima"]                    |
|     plugins      |            path            |       插件库文件路径       | string[] | ["/usr/local/lib/libtpm_boot_verifier.so", "/usr/local/lib/libtpm_ima_verifier.so"] |

#### attestation_service/attestation_service/Cargo.toml

在根目录下的attestation_service/attestation_service/Cargo.toml文件中修改features

当为docker构建时为docker_build

当为rpm构建时为rpm_build

![输入图片说明](https://foruda.gitee.com/images/1747300931159837528/617c4777_15438102.png "屏幕截图")


## 构建docker镜像

### 上传与key_manager交互的证书

在代码的根目录下创建certs目录，将key_manager生成的ra_client_key.pem、ra_client_cert.pem、km_cert.pem证书放入

此处需要注意一点，service服务依赖key_manager密钥管理服务，在代码根目录docker-compose.yaml文件中存在key_manager服务相关配置，此处不赘述如何配置并启动key_manager服务

### 构建镜像

首先执行cargo check，检查项目，并生成构建docker镜像所需的必备文件

```
cargo check
```

构建service

```
docker-compose --env-file .env build --no-cache --progress=plain
```

启动容器

```
docker-compose --env-file .env --verbose up -d attestation_service
```

## rpm部署



部署mysql,redis,kafka中间件，并将地址端口配置在.env.rpm文件中

在server部署环境安装librdkafka

```
# ubtun安装kafka
sudo apt remove librdkafka-dev
wget https://github.com/edenhill/librdkafka/archive/refs/tags/v2.3.0.tar.gz
tar -xzf v2.3.0.tar.gz
cd librdkafka-2.3.0/
./configure
make
sudo make install

# openeuler安装kafka
sudo dnf install -y git gcc gcc-c++ make cmake openssl-devel zlib-devel python3 && \
git clone --branch v2.3.0 https://gitee.com/mirrors/librdkafka.git && \
cd librdkafka && \
./configure --prefix=/usr/local && \
make -j$(nproc) && \
sudo make install && \
sudo ldconfig

export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH


#最后查看版本号2.3.0
pkg-config --modversion rdkafka
```

构建rpm包，运行rpm_build.sh

```
sh script/rpm_build.sh -s
```

构建完成后，rpm包在/root/rpmbuild/RPMS/x86_64/ra-server-0.0.1-1.x86_64.rpm

**卸载**

```
rpm -e ra-server-0.0.1-1.x86_64
```

**安装**

```
rpm -ivh --nodeps ra-server-0.0.1-1.x86_64.rpm
```

直接在窗口执行命令即可启动

```
attestation_service
```

## 调用接口&&环境预置数据

### 环境数据预置内容

server端需要预置的数据：

1. tpm_boot策略，tpm_ima策略

    2. agent插件AK根证书
    2. 基线、策略jwt格式导入所使用的证书
    2. ima度量基线

以上数据均在Challenge_Request_Challenge_Response_Environment_Preparation.md文档

### 接口调用

参考Complete_List_of_Management_Tool_Commands.md文档，使用cli_tool工具调用接口