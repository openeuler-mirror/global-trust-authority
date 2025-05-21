# Key Manager
## Introduction
Key Manager is a key broker component based on a 3rd KMS (e.g. OpenBao), It acts as a key vault of GTA remote attestation service and provides credentials such as several signing keys.These keys can be well imported, stored and exported thanks to the 3rd party KMS.

## Deployment
Key Manager supports both RPM and Docker installation.
### Prerequisites
#### 1. Dependencies
* rust
```shell
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```
* openssl
```shell
dnf install openssl openssl-devel #Linux (RHEL/CentOS/Fedora)
apt update && apt install openssl libssl-dev #Linux (Debian/Ubuntu)
```
#### 2.Generate test certificates (optional)
Currently, the Key Manager communicates using ​Mutual TLS , so the corresponding certificate configuration is required.
Generate the MTLS certificate using the following script under the current path:
```shell
# The IP of the currently deployed server is used for the certificate SAN field
bash script/test_certificate_generation.sh -p <Specified path> -i <The IP of the currently deployed server>
```
The current certificate will affect the subsequent installation of docker. It is recommended to place it in the current global-trust-authority/certs directory.
#### 3.Deployment of openbao
Download the corresponding version according to the system (the current corresponding openbao version is v2.2.0).
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
Install openbao using the following command
```shell
# Ubuntu/Debian
dpkg -i bao_2.2.0_linux_amd64.deb
# CentOS/RHEL
rpm -ivh --nodeps bao_2.2.0_linux_amd64.rpm
```
Modify the current configuration file of openbao, which is located in the path /etc/openbao/openbao.hcl.
Modify it to the following configuration:
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
Start the current openbao using the following command
```shell
systemctl start openbao.service
```
Import environment variables
```shell
export BAO_ADDR=http://127.0.0.1:8200/
```
Execute the openbao initialization command
```shell
bao operator init
```
Some of the results obtained are as follows:
```text
Unseal Key 1: DYd304ycrZXtzCool+2MNaEo3r/XAu4YjgBj04UiXN/+
Unseal Key 2: D8LNBo/76HRPKl/AMjLCkvCFLl23BenURZec7ov+szjW
Unseal Key 3: qXkzqd9NlemvMOXeYcqBsEp4b47hYlFZ0H0cxusb/pFj
Unseal Key 4: jhV2JGuuBgkyyWHz7ZQlAq1ov5egGqK7XHO68fQPo5f1
Unseal Key 5: ZVR+AopsEgJ2RnDE3AmtJpPYLkaPSInHicJ/ZPzQNzaL

Initial Root Token: s.tNAqbGc4RI9TKVaqwJjsqibP
```
Record the unseal key and root token.
Use the following command to unblock openbao
```shell
# The current unseal key comes from the above-mentioned console print content. Using three can unseal the current openbao
bao operator unseal <unseal key>
```
### Install Key Manager with RPM
#### 1.Install dependencies
```shell
sudo yum install -y gcc rpm-build openssl-devel
```
#### 2.Build the RPM package
```shell
# Enter the project root directory and execute the following command to build the rpm package
sh key_manager/script/rpm_build.sh
```
#### 3.Install RPM
```shell
sudo rpm -ivh ~/rpmbuild/RPMS/aarch64/global-trust-authority-key-manager-0.1.0-1.aarch64.rpm
```
#### 4.Start Key Manager
The current rpm will be installed in the directory /usr/local/key_manager/bin to modify the configuration file in the current path
```shell
vim /usr/local/key_manager/bin/.env
# The configuration files that need to be modified are as follows
ROOT_CA_CERT_PATH=  # The path of the root CA certificate in the MTLS certificate
KEY_MANAGER_CERT_FILE_PATH= # The certificate of key Manager issued by the current root CA
KEY_MANAGER_KEY_FILE_PATH= # The private key of the key Manager issued by the current root CA
KEY_MANAGER_ROOT_TOKEN= # The root token currently accessed by openbao
KEY_MANAGER_SECRET_ADDR= # The current openbao access address can be filled in as http://127.0.0.1:8200/ by default
```
Start the current Key Manager using the background startup command
```shell
./key_managerd &
```
The log path can refer to this configuration option in the current.env**KEY_MANAGER_LOG_PATH**
### Install Key Manager with Docker
#### 1.docker
```shell
# Ubuntu/Debian
sudo apt update
sudo apt install -y apt-transport-https ca-certificates curl gnupg lsb-release

# CentOS/RHEL
sudo yum install -y yum-utils device-mapper-persistent-data lvm2
```
#### 2.docker packaging image
Currently, the Key Manager needs to use two docker base images:
```dockerfile
rust:1.85
debian:bookworm-slim
```
The current deployment requires the use of MTLS two-way certificates. Therefore, the certificates need to be placed in the global-trust-authority/certs folder.
Under the current Key Manager directory, use the following command to package the current Key Manager image
```shell
docker compose build key_manager
```
#### 3.Start the docker image
```shell
docker run -d -p 8082:8082 key_manager:latest
```
## Query key
The current service provides a RestfulAPI interface externally for external key query. The interface parameters are as follows:
```text
GET /v1/vault/get_signing_keys
```
After starting the current Key Manager normally, the following curl command can be used to test whether the current Key Manager starts normally. If the result can be queried normally, it indicates that the deployment of the current Key Manager is successful
```shell
# ra_client_cert.pem: The current client certificate issued by the root CA
# ra_client_key.pem: The current client private key issued by the root CA
# km_cert.pem: Current root CA certificate
curl  --cert ra_client_cert.pem \ 
      --key  ra_client_key.pem \
      --cacert km_cert.pem \
      --resolve "key_manager:8082:127.0.0.1" \
      https://key_manager:8082/v1/vault/get_signing_keys
```
## Import key
### Precondition
1. The openbao service has been installed and is operating normally
2. The Key Manager has been started normally
### Import using the Key Manager command-line tool
```shell
./key_manager put --key_name <KEY_NAME> --algorithm <ALGORITHM> --encoding <ENCODING> --key_file <KEY_FILE>
```
#### Example
1. Generate the key file rsa_3072.key
2. Execute the following command to import the key with the name "TSK", the encoding method "PEM" and the encryption algorithm "RSA 3072"
```shell
# Enter the bin installation directory of Key Manager and execute the following command for import
./key_manager put --key_name TSK --algorithm rsa_3072 --encoding pem --key_file rsa_3072.key
```
3. The following information indicates a successful import
```shell
success to handle command
```
#### View help
Execute the following command to view the tool help information
```shell
./key_manager put --help
```
## Test data generation
The corresponding test data can be generated by using the current key_manager/script/generate_test_data.sh.
### rpm
Copy the current script to the directory /usr/local/key_manager/bin
```shell
cp key_manager/script/generate_test_data.sh /usr/local/key_manager/bin
```
Execute the current test data generation script. An example is as follows:
```shell
cd /usr/local/key_manager/bin
# indicates that two versions of data in rsa3072 format are currently prefabricated for the three types of private keys
bash generate_test_data.sh rsa_3072 2
```
### docker
Use the following command to view the docker container ID of the current Key Manager
```shell 
docker ps
```
Enter the current command line of docker
```shell
docker exec -it <Container ID> /bin/bash
```
Enter the current container deployment directory /opt/key_manager and execute the current script
```shell
cd /opt/key_manager
# indicates that two versions of data in rsa3072 format are currently prefabricated for the three types of private keys
bash generate_test_data.sh rsa_3072 2
```