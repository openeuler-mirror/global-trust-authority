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
The Key Manager requires mTLS communication. Generate certificates using:
```shell
# Using the server IP for certificate SAN field
bash script/test_certificate_generation.sh -p <Specified path> -i <The IP of the currently deployed server>
```
>Recommendation: Store certificates in global-trust-authority/certs for Docker compatibility.
#### 3.OpenBao Installation
Download the appropriate package for your architecture:
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
Installation commands:
```shell
# Ubuntu/Debian
dpkg -i bao_2.2.0_linux_amd64.deb
# CentOS/RHEL
rpm -ivh --nodeps bao_2.2.0_linux_amd64.rpm
```
Edit the configuration file at /etc/openbao/openbao.hcl:
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
Initialize OpenBao
```shell
systemctl start openbao.service
export BAO_ADDR=http://127.0.0.1:8200/
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
Securely store the unseal keys and root token displayed in the output.
```shell
# The current unseal key comes from the above-mentioned console print content. Using three can unseal the current openbao
bao operator unseal <unseal key>
```
### Deployment by rpm
#### 1.Install dependencies
```shell
sudo yum install -y gcc rpm-build openssl-devel
```
#### 2.Build RPM package
```shell
sh key_manager/script/rpm_build.sh
```
#### 3.Install Key Manager
```shell
sudo rpm -ivh ~/rpmbuild/RPMS/aarch64/global-trust-authority-key-manager-0.1.0-1.aarch64.rpm
```
#### 4.Configure Environment
Edit /usr/local/key_manager/bin/.env:
```shell
ROOT_CA_CERT_PATH=/path/to/km_cert.pem
KEY_MANAGER_CERT_FILE_PATH=/path/to/key_manager_server_cert.pem
KEY_MANAGER_KEY_FILE_PATH=/path/to/key_manager_server_key.pem
KEY_MANAGER_ROOT_TOKEN=your_openbao_root_token
KEY_MANAGER_SECRET_ADDR=http://127.0.0.1:8200/
```
#### 5.Start Service
```shell
/usr/local/key_manager/bin/key_managerd &
```
### Deployment by docker
#### 1.Install Docker
```shell
# Debian/Ubuntu
sudo apt-get update && sudo apt-get install -y docker-ce

# RHEL/CentOS
sudo yum install -y docker-ce docker-ce-cli
```
#### 2.Build Container
The deployment requires MTLS two-way certificates, which must be placed in the global-trust-authority/certs directory.
```shell
docker compose build key_manager
```
#### 3.Start the docker image
```shell
docker run -d -p 8082:8082 key_manager:latest
```
## API Usage
### Key Query Endpoint
```text
GET /v1/vault/get_signing_keys
```
Example request:
```shell
# ra_client_cert.pem: The current client certificate issued by the root CA
# ra_client_key.pem: The current client private key issued by the root CA
# km_cert.pem: Current root CA certificate
curl  --cert ra_client_cert.pem \ 
      --key  ra_client_key.pem \
      --cacert km_cert.pem \
      https://key_manager:8082/v1/vault/get_signing_keys
```
## Import key
### Precondition
1. The openbao service has been installed and is operating normally
2. The Key Manager has been started normally
3. If the current key_manager is connected to the attestation_service, it requires at least >=2 versions of key data.
### Import using the Key Manager command-line tool
```shell
./key_manager put --key_name <KEY_NAME> --algorithm <ALGORITHM> --encoding <ENCODING> --key_file <KEY_FILE>
```
### Parameter Specifications
| Parameter    | Required | Values  | Allowed Values    | Description                      |
|--------------|----------|---------|-------------------|----------------------------------|
| --key_name   | Yes      | String  | `NSK`,`FSK`,`TSK` | Unique identifier for the key    |
| --algorithm  | Yes      | String  | `RSA_3072`        | Encryption algorithm for the key |
| --encoding   | Yes      | String  | `PEM`             | Encoding format for the key      |
| --key_file   | Yes      | String  | -                 | Path to key file                 |
> **Note**: The current key algorithm format only supports RSA_3072.
### Example
1. Generate the key file rsa_3072.key
2. Execute the following command to import the key with the name "TSK", the encoding method "PEM" and the encryption algorithm "RSA 3072"
```shell
./key_manager put --key_name TSK --algorithm rsa_3072 --encoding pem --key_file rsa_3072.key
```
The following information indicates a successful import
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
# prefabricate one instance each of RSA3072 format are currently prefabricated for the three types of private keys
bash generate_test_data.sh rsa_3072 1
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
# prefabricate one instance each of RSA3072 format data for the three types of private keys
bash generate_test_data.sh rsa_3072 1
```