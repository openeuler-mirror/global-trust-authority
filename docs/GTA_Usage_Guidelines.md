# GTA Usage Guidelines

## Pull Code

```
git clone https://gitee.com/openeuler/global-trust-authority.git
```

## Modify the configuration file

#### key_manager .env

The .env file configures the KeyManager module settings. In an RPM installation, these configurations need to be modified, whereas in a Docker environment, no changes are required.
The current configuration is set as follows:

|         Field Name         |            Field Meaning             | Field Type |        Default/Example Values        |
|:--------------------------:|:------------------------------------:|:----------:|:------------------------------------:|
|      KEY_MANAGER_PORT      |           The startup port           |   string   |                 8082                 |
|     ROOT_CA_CERT_PATH      |           Current mTLS CA            |   string   |         /path/to/km_cert.pem         |
| KEY_MANAGER_CERT_FILE_PATH | The current server-side certificate. |   string   | /path/to/key_manager_server_cert.pem |
| KEY_MANAGER_KEY_FILE_PATH  |  The current server's private key.   |   string   | /path/to/key_manager_server_key.pem  |
|   KEY_MANAGER_LOG_LEVEL    |        The current log level         |   string   |                 info                 |
|    KEY_MANAGER_LOG_PATH    |  The directory path for log files.   |   string   | /var/log/key_manager/key_manager.log |
|   KEY_MANAGER_ROOT_TOKEN   |    The access token for OpenBao.     |   string   |      s.8aIUbu85l5nJggtq5Unml4Kg      |
|  KEY_MANAGER_SECRET_ADDR   |   The access endpoint for OpenBao    |   string   |        http://127.0.0.1:8200/        |

#### .env / .env.rpm

```
vim .env
```

The .env file configures key configurations such as database, middleware, flow limiting, etc. related to the remote proof service in the docker container

#### server_config.yaml / server_config_rpm.yaml

Configuration of nonce, token, policy, certificate, baseline on server side

|     Configuration Level     |          Field Name          |                         Field Meaning                          | Field Type |                                    Default/Example Values                                     |
| :--------------: | :------------------------: |:--------------------------------------------------------------:| :------: |:---------------------------------------------------------------------------------------------:|
|  key_management  |     vault_get_key_url      |           Vault service URL for getting signing keys           |  string  |                      "https://127.0.0.1:8082/v1/vault/get_signing_keys"                       |
|  key_management  |      is_require_sign       | Whether to request a signature, this setting cannot be changed | boolean  |                                             true                                              |
| token_management |            jku             |                          JWK Set URL                           |  string  |                                             "jku"                                             |
| token_management |            kid             |                             Key ID                             |  string  |                                             "kid"                                             |
| token_management |         exist_time         |              Token Existence Time (milliseconds)               | integer  |                                            600000                                             |
| token_management |            iss             |                             Issuer                             |  string  |                                             "iss"                                             |
| token_management |        eat_profile         |                          EAT profile                           |  string  |                                         "eat_profile"                                         |
| token_management |         mq_enabled         |               Whether message queuing is enabled               | boolean  |                                             false                                             |
| token_management |        token_topic         |                       Token subject name                       |  string  |                                       "gta_token_topic"                                       |
|      policy      |  export_policy_file.name   |                        Policy File Name                        | string[] |                                    ["tpm_boot", "tpm_ima"]                                    |
|      policy      |  export_policy_file.path   |                        Policy File Path                        | string[] | ["/var/test_docker/app/export_policy/tpm_boot.rego", "/var/test_docker/app/export_policy/tpm_ima.rego"] |
|      policy      | is_verify_policy_signature |              Whether to verify policy signatures               | boolean  |                                             false                                             |
|      policy      |  single_user_policy_limit  |               Limit number of policies per user                | integer  |                                              30                                               |
|      policy      | policy_content_size_limit  |               Policy content size limit (bytes)                | integer  |                                              500                                              |
|      policy      |  query_user_policy_limit   |                    Query user policy limit                     | integer  |                                              10                                               |
|       cert       |   single_user_cert_limit   |            Limit number of single-user certificates            | integer  |                                              10                                               |
|      nonce       |     nonce_valid_period     |                Nonce validity period (seconds)                 | integer  |                                              120                                              |
|      nonce       |        nonce_bytes         |                       nonce byte length                        | integer  |                                              64                                               |
|     plugins      |            name            |                          Plugin Name                           | string[] |                                    ["tpm_boot", "tpm_ima"]                                    |
|     plugins      |            path            |                    Plugin library file path                    | string[] |      ["/usr/local/lib/libtpm_boot_verifier.so", "/usr/local/lib/libtpm_ima_verifier.so"]      |

#### attestation_service/attestation_service/Cargo.toml

In the attestation_service/attestation_service/Cargo.toml file in the root directory, change the features

docker_build for docker builds

rpm_build for rpm builds
![输入图片说明](https://foruda.gitee.com/images/1747300931159837528/617c4777_15438102.png "屏幕截图")


#### agent_config.yaml
Configuration of agent ip, server url, log file and plugins information on agent side


| Configuration Level | Field Name | Field Meaning | Field Type | Default/Example Values |
|-------------------|------------|---------------|------------|----------------------|
| agent | listen_address | IP address for the agent to listen | string | "0.0.0.0" |
| agent | listen_port | Port number for the agent to listen | integer | 8088 |
| agent | uuid | Unique agent identifier, same as common name field in IAK certificate | string | "a4e7c719-6b05-4ac6-b95a-7e71a9d6f9d5" |
| agent | user_id | Unique identifier for the user | string | "test_01" |
| server | server_url | Base URL of the attestation server | string | "http://127.0.0.1:8080" |
| server | tls.cert_path | TLS certificate path | string | "/path/to/cert.pem" |
| server | tls.key_path | TLS private key path | string | "/path/to/key.pem" |
| server | tls.ca_path | CA certificate path | string | "/path/to/key.pem" |
| logging | level | Logging level | string | "info" (options: trace, debug, info, warn, error) |
| logging | file | Log file Path | string | "/var/log/ra-agent.log" |
| plugins | name | Plugin name | string | "tpm_boot", "tpm_ima" |
| plugins | path | Plugin so path | string | "/usr/lib64/libtpm_boot_attester.so", "/usr/lib64/libtpm_ima_attester.so" |
| plugins | policy_id | List of policy IDs associated with the plugin | string[] | [] |
| plugins | enabled | Whether the plugin is enabled | boolean | true |
| plugins | params.attester_type | attester type | string | "tpm_boot", "tpm_ima" |
| plugins | params.tcti_config | TPM Command Transmission Interface configuration | string | "device" (options: device, mssim, swtpm, tabrmd, libtpm) |
| plugins | params.ak_handle | Attestation Key handle, Need to create in advance, please refer to the key handle range: https://trustedcomputinggroup.org/wp-content/uploads/Registry-of-Reserved-TPM-2.0-Handles-and-Localities-Version-1.2-Revision-1.00_pub.pdf | integer | 0x81010020 |
| plugins | params.ak_nv_index | AK Cert nv_index, iak certificate application reference: https://trustedcomputinggroup.org/wp-content/uploads/TPM-2p0-Keys-for-Device-Identity-and-Attestation_v1_r12_pub10082021.pdf | integer | 0x150001b |
| plugins | params.pcr_selections.banks | PCR banks to use | array | [0,1,2,3,4,5,6,7] for tpm_boot, [10] for tpm_ima |
| plugins | params.pcr_selections.hash_alg | The PCR hash algorithm selected and the supported algorithms depend on the TPM chip | string | "sha256" (options: sha1, sha256, sha384, sha512, sm3) |
| plugins | params.quote_signature_scheme.signature_alg | Signature algorithm for quotes | string | "rsassa" (options: rsapss, rsassa, ecdsa) |
| plugins | params.quote_signature_scheme.hash_alg | Hash algorithm for quotes | string | "sha256" (options: sha1, sha256, sha384, sha512, sm3) |
| plugins | params.log_file_path | Measurement log file path | string | "/sys/kernel/security/tpm0/binary_bios_measurements" for tpm_boot, "/sys/kernel/security/ima/ascii_runtime_measurements" for tpm_ima |
| schedulers | name |  Scheduler task name | string | "challenge", "config_sync" |
| schedulers | retry_enabled | Whether to enable retry mechanism | boolean | true/false |
| schedulers | intervals | Task execution interval in seconds | integer | 86400 (24 hours) for challenge, 300 (5 minutes) for config_sync |
| schedulers | initial_delay.min_seconds | Minimum initial delay in seconds | integer | 1 |
| schedulers | initial_delay.max_seconds | Maximum initial delay in seconds | integer | 60 |
| schedulers | max_retries | Maximum number of retry attempts | integer | 1 |
| schedulers | enabled | Whether the scheduler is enabled | boolean | true |

#### attestation_agent.service
The agent supports auto-start at startup, and this file cannot be customized and modified

## Deployment by docker

### key_manager

[Key Manager Installation](./key_manager_install.md#L108)

### attestation_service

#### Uploading certificates that interact with key_manager

Create a certs directory in the root directory of the code, and put the ra_client_key.pem, ra_client_cert.pem, and km_cert.pem certificates generated by key_manager in the specified directory.

```
.../global-trust-authority/certs
```

One thing to note here is that the service relies on the key_manager key management service, and there is a key_manager service configuration in the docker-compose.yaml file in the root directory of the code, so we won't go into the details of how to configure and start the key_manager service here.

#### Build image

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

#### Demo

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

## Deployment by rpm

### key_manager

[Key Manager Installation](./key_manager_install.md#L82)

### attestation_service

#### Uploading TLS certificates with key_manager and install librdkafka

Create the certs folder in the /etc/attestation_server/certs directory and place the ra_client_key.pem, ra_client_cert.pem and km_cert.pem certificates into the specified directory.

```
/etc/attestation_server/certs
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
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
```

Last viewed version number 2.3.0
```
pkg-config --modversion rdkafka
```

#### Build the rpm package

Build the rpm package, run rpm_build.sh

```
sh script/rpm_build.sh -s
```

Take the x86 architecture as an example, after the build is complete, the rpm package is in /root/rpmbuild/RPMS/x86_64/ra-server-0.0.1-1.x86_64.rpm

#### Install the rpm package

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

#### Deployment
##### Pre-middleware
Install and run these components before deployment:

- **MySQL**

- **Redis**

- **ZooKeeper**

- **Kafka**

> **Note**: ZooKeeper ≥3.6 uses port 8080 (UI) by default - change if conflicting.

##### start
Execute the command to start the service

```
attestation_service
```

The following display appears, proving that the service was started successfully

![输入图片说明](https://foruda.gitee.com/images/1747723422317992291/83668a75_15438102.png "屏幕截图")

#### Uninstall the rpm package

```
rpm -e ra-server-0.0.1-1.x86_64
rpm -qa | grep ra-server
```

After executing the command, there is no output, proving that the service was uninstalled successfully

### attestation_agent

#### Build the rpm package

Build the rpm package, run rpm_build.sh

```
sh script/rpm_build.sh -a
```

Take the x86 architecture as an example, after the build is complete, the rpm package is in /root/rpmbuild/RPMS/x86_64/ra-agent-0.0.1-1.x86_64.rpm

#### Install the rpm package

Install the rpm package

```
rpm -ivh --nodeps ra-agent-0.0.1-1.x86_64.rpm
```

The following message appears, proving that the rpm package was installed successfully

```
rpm: RPM should not be used directly install RPM packages, use Alien instead!
rpm: However assuming you know what you are doing...
Verifying...                          ################################# [100%]
Preparing...                          ################################# [100%]
Updating / installing...
   1:ra-agent-0.0.1-1                 ################################# [100%]
```
#### Deployment
##### start
Execute the command to start the service

```
systemctl start attestation_agent.service
```

Use `systemctl status agent.service` to check the service status. If the service is active, it indicates the agent node has started successfully.

#### Uninstall the rpm package

```
rpm -e ra-agent-0.0.1-1.x86_64
rpm -qa | grep ra-agent
```

After executing the command, there is no output, proving that the agent service was uninstalled successfully

## Interact with Rest API && environment preset data

### Environmental data preset contents

Data that needs to be preset on the server side:

1. tpm_boot policy, tpm_ima policy
2. Certificate chain for AIK validation
3. Public key certificate for validation signature of baseline/policy
4. ima metrics baseline


Data that needs to be preset on the agent side:

1. The device needs to have the TPM, which includes the hardware TPM, vTPM, or fTPM.
2. The device must be preset with the IAK certificate in the TPM chip

All of the above data is in the Challenge_Request_Challenge_Response_Environment_Preparation.md document.

### Interact with Rest API

Refer to the Complete_List_of_Management_Tool_Commands.md documentation to Interact with the Rest API using the cli_tool.