# GTA Usage Guidelines

## Pull Code

```
git clone https://gitee.com/openeuler/global-trust-authority.git
```

## Modify the configuration file

#### .env / .env.rpm

```
vim .env
```

The .env file configures key configurations such as database, middleware, flow limiting, etc. related to the remote proof service in the docker container

#### server_config.yaml / server_config_rpm.yaml

Configuration of nonce, token, policy, certificate, baseline on server side

|     Configuration Level     |          Field Name          |               Field Meaning                | Field Type |                                    Default/Example Values                                     |
| :--------------: | :------------------------: |:------------------------------------------:| :------: |:---------------------------------------------------------------------------------------------:|
|  key_management  |     vault_get_key_url      | Vault service URL for getting signing keys |  string  |                     "https://127.0.0.1:8082/v1/vault/get_signing_keys"                      |
|  key_management  |      is_require_sign       |       Whether to request a signature       | boolean  |                                             true                                              |
| token_management |            jku             |                JWK Set URL                 |  string  |                                             "jku"                                             |
| token_management |            kid             |                   Key ID                   |  string  |                                             "kid"                                             |
| token_management |         exist_time         |    Token Existence Time (milliseconds)     | integer  |                                            600000                                             |
| token_management |            iss             |                   Issuer                   |  string  |                                             "iss"                                             |
| token_management |        eat_profile         |                EAT profile                 |  string  |                                         "eat_profile"                                         |
| token_management |         mq_enabled         |     Whether message queuing is enabled     | boolean  |                                             false                                             |
| token_management |        token_topic         |             Token subject name             |  string  |                                       "gta_token_topic"                                       |
|      policy      |  export_policy_file.name   |              Policy File Name              | string[] |                                    ["tpm_boot", "tpm_ima"]                                    |
|      policy      |  export_policy_file.path   |              Policy File Path              | string[] | ["/var/test_docker/app/export_policy/tpm_boot", "/var/test_docker/app/export_policy/tpm_ima"] |
|      policy      | is_verify_policy_signature |    Whether to verify policy signatures     | boolean  |                                             false                                             |
|      policy      |  single_user_policy_limit  |     Limit number of policies per user      | integer  |                                              30                                               |
|      policy      | policy_content_size_limit  |     Policy content size limit (bytes)      | integer  |                                              500                                              |
|      policy      |  query_user_policy_limit   |          Query user policy limit           | integer  |                                              10                                               |
|       cert       |   single_user_cert_limit   |  Limit number of single-user certificates  | integer  |                                              10                                               |
|      nonce       |     nonce_valid_period     |      Nonce validity period (seconds)       | integer  |                                              120                                              |
|      nonce       |        nonce_bytes         |             nonce byte length              | integer  |                                              64                                               |
|     plugins      |            name            |                Plugin Name                 | string[] |                                    ["tpm_boot", "tpm_ima"]                                    |
|     plugins      |            path            |          Plugin library file path          | string[] |      ["/usr/local/lib/libtpm_boot_verifier.so", "/usr/local/lib/libtpm_ima_verifier.so"]      |

#### attestation_service/attestation_service/Cargo.toml

In the attestation_service/attestation_service/Cargo.toml file in the root directory, change the features

docker_build for docker builds

rpm_build for rpm builds
![输入图片说明](https://foruda.gitee.com/images/1747300931159837528/617c4777_15438102.png "屏幕截图")


## Building a docker image

### Uploading certificates that interact with key_manager

Create a certs directory in the root directory of the code, and put the ra_client_key.pem, ra_client_cert.pem, and km_cert.pem certificates generated by key_manager in the specified directory.

```
.../global-trust-authority/certs
```

One thing to note here is that the service relies on the key_manager key management service, and there is a key_manager service configuration in the docker-compose.yaml file in the root directory of the code, so we won't go into the details of how to configure and start the key_manager service here.

### Build image

First run a cargo check to inspect the project and generate the necessary files for building the docker image

The current version of docker builds only supports Debian, and subsequent versions will support other mirrors.
```
cargo check
```

build service

```
docker-compose --env-file .env build --no-cache --progress=plain
```

Start the container

```
docker-compose --env-file .env --verbose up -d attestation_service
```

### Demo

Enter the following command to view the container startup

```
docker ps
```

The following effect occurs, indicating that the container was started successfully

![输入图片说明](https://foruda.gitee.com/images/1747723385663352173/c8b22c22_15438102.png "屏幕截图")

Stop the docker container

```
docker stop CONTAINER ID
```

## rpm deployment

### Uploading TLS certificates with key_manager and install librdkafka

Create the certs folder in the /tmp directory and place the a_client_key.pem, ra_client_cert.pem and km_cert.pem certificates into the specified directory.

```
/tmp/certs
```

One thing to note here is that the service relies on the key_manager key management service, and there is a key_manager service configuration in the docker-compose.yaml file in the root directory of the code, so we won't go into the details of how to configure and start the key_manager service here.

Installing librdkafka in a server deployment environment

```
sudo dnf install -y git gcc gcc-c++ make cmake openssl-devel zlib-devel python3 && \
git clone --branch v2.3.0 https://gitee.com/mirrors/librdkafka.git && \
cd librdkafka && \
./configure --prefix=/usr/local && \
make -j$(nproc) && \
sudo make install && \
sudo ldconfig

export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
```

Last viewed version number 2.3.0
```
pkg-config --modversion rdkafka
```

### Build the rpm package

Build the rpm package, run rpm_build.sh

```
sh script/rpm_build.sh -s
```

Take the x86 architecture as an example, after the build is complete, the rpm package is in /root/rpmbuild/RPMS/x86_64/ra-server-0.0.1-1.x86_64.rpm

### Install the rpm package

Install the rpm package

```
rpm -ivh --nodeps ra-server-0.0.1-1.x86_64.rpm
```

The following message appears, proving that the rpm package was installed successfully

```
rpm: RPM should not be used directly install RPM packages, use Alien instead!
rpm: However assuming you know what you are doing...
Verifying...                          ################################# [100%]
Preparing...                          ################################# [100%]
Updating / installing...
   1:ra-server-0.0.1-1                ################################# [100%]
```

### Run the rpm package

Execute the command to start the service

```
attestation_service
```

The following display appears, proving that the service was started successfully

![输入图片说明](https://foruda.gitee.com/images/1747723422317992291/83668a75_15438102.png "屏幕截图")

### Uninstall the rpm package

```
rpm -e ra-server-0.0.1-1.x86_64
rpm -qa | grep ra-server
```

After executing the command, there is no output, proving that the service was uninstalled successfully

## Interact with Rest API && environment preset data

### Environmental data preset contents

Data that needs to be preset on the server side:

1. tpm_boot policy, tpm_ima policy
2. Certificate chain for AIK validation
3. Public key certificate for validation signature of baseline/policy
4. ima metrics baseline

All of the above data is in the Challenge_Request_Challenge_Response_Environment_Preparation.md document.

### Interact with Rest API

Refer to the Complete_List_of_Management_Tool_Commands.md documentation to Interact with the Rest API using the cli_tool.