# Server Preparation

## Strategy-related data preparation

Added tpm_boot policy and tpm_ima policy

### tpm_boot

```
package verification

# Extract secure_boot status: yes if any matching entry found with yes, else no
default secure_boot = "no"
secure_boot = "yes" {
    some i, j
    logs := input.evidence.logs
    logs[i].log_type == "TcgEventLog"
    event := logs[i].log_data[j]
    event.event_type == "EV_EFI_VARIABLE_DRIVER_CONFIG"
    event.event.unicode_name == "SecureBoot"
    lower(event.event.variable_data.enabled) == "yes"
}

# Extract log_status from first TcgEventLog log
log_status = status {
    some i
    logs := input.evidence.logs
    logs[i].log_type == "TcgEventLog"
    status := logs[i].log_status
}


# Check if pcrs 0-7 are present in any hash algorithm (sha1, sha256, sha384, sha512)
pcr_present {
    all := {x | x := [0,1,2,3,4,5,6,7][_]}
    measured := {pcr.pcr_index | pcr := input.evidence.pcrs.pcr_values[_]}
    all_pcrs_subset := all - measured
    count(all_pcrs_subset) == 0
}

# Attestation valid if all conditions met
default attestation_valid = false
attestation_valid {
    secure_boot == "yes"
    log_status == "replay_success"
    pcr_present
}

# Output result
result = {
    "policy_matched": attestation_valid,
    "custom_data": {
        "hash_alg": input.evidence.pcrs.hash_alg
    }
}

```

### tpm_ima

```
package verification

# Extract log_status from first tpm_ima log
log_status = status {
    some i
    logs := input.evidence.logs
    logs[i].log_type == "ImaLog"
    status := logs[i].log_status
}

ref_value_match_status = status {
    some i
    logs := input.evidence.logs
    logs[i].log_type == "ImaLog"
    status := logs[i].ref_value_match_status
}

# Check if pcrs 10 is present in any hash algorithm (sha1, sha256, sha384, sha512)
pcr_present {
    all := {x | x := [10][_] }
    measured := {pcr.pcr_index | pcr := input.evidence.pcrs.pcr_values[_]}
    all_pcrs_subset := all - measured
    count(all_pcrs_subset) == 0
}

# Attestation valid if all conditions met
default attestation_valid = false
attestation_valid {
    log_status == "replay_success"
    ref_value_match_status == "matched"
    pcr_present
}

# Output result
result = {
    "policy_matched": attestation_valid,
    "custom_data": {
        "hash_alg": input.evidence.pcrs.hash_alg
    }
}
```

### virtCCA
Fill in the contents of the UEFI baseline and virtCCAToken into predefined_values.
```
package verification

# Predefined values for verification
predefined_values := {
    "firmware_state": {
        "grub_cfg": "d76740a196dc8c96b5983dd2177a84ba893e01b08430bae81d90112b7eefa5cf",
        "kernel": "e14bd37fd6d957b48d3ddde9be14c6d977f74127a6c6e4846c6b2a9f4fe48b41",
        "initramfs": "fc7269847648cdab5323a4213a6d7b9a47512851beae8106a81b3e507e6dfc79",
        "grub_image_list": ["87276d2d4f3d17714e120d5b68694873880043e5abe7747fb4a47b5f6f38ca7a"]
    },
    "vcca_rpv": "02000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "vcca_rim": "b23d801b7a7d00e53dc636f918237a62f8a30df39f46db9af7cd213713a041d8",
    "vcca_rem0": "5a408cfa02bc28f677a937348e2d8c34519a4c61e4934ca911e5a3e12d2a877d",
    "vcca_rem1": "646fdfc8b716bf958471a20378f178c472679216c911ddd0349cd74924eda7e9",
    "vcca_rem2": "d5baa6203ec24a54e92ee9d3c1e678a2f67e3a2cd4d38111606a710fa247c93e",
    "vcca_rem3": "0000000000000000000000000000000000000000000000000000000000000000"
}

default attestation_valid = false

# Main validation rule that checks all required fields
attestation_valid {
    # Check firmware_state if present
    input.vcca_ccel_log_data.firmware_state
    objects_equal(input.vcca_ccel_log_data.firmware_state, predefined_values.firmware_state)
    
    # Check other required fields
    input.vcca_rpv == predefined_values.vcca_rpv
    input.vcca_rim == predefined_values.vcca_rim
    input.vcca_rem0 == predefined_values.vcca_rem0
    input.vcca_rem1 == predefined_values.vcca_rem1
    input.vcca_rem2 == predefined_values.vcca_rem2
    input.vcca_rem3 == predefined_values.vcca_rem3
}

# Alternative rule when firmware_state is not present
attestation_valid {
    not input.vcca_ccel_log_data.firmware_state
    
    # Check other required fields
    input.vcca_rpv == predefined_values.vcca_rpv
    input.vcca_rim == predefined_values.vcca_rim
    input.vcca_rem0 == predefined_values.vcca_rem0
    input.vcca_rem1 == predefined_values.vcca_rem1
    input.vcca_rem2 == predefined_values.vcca_rem2
    input.vcca_rem3 == predefined_values.vcca_rem3
}

# Helper function to compare objects
objects_equal(a, b) {
    keys_a := {k | a[k]}
    keys_b := {k | b[k]}
    keys_a == keys_b
    
    values_match := {k | a[k] == b[k]}
    count(keys_a) == count(values_match)
}

result = {
    "policy_matched": attestation_valid
}
```

## Certificate-related preparations

### Importing the plugin's ak certificate

Check out the method for generating ak root certificates on the agent side, and then call the add certificate interface to add the certificate

### Importing certificates for baselines and strategies

Just generate your own certificate here

```
1. Generate private key
sha256WithRSAEncryption:
openssl genpkey -algorithm RSA -out rsa_2048_private_key.pem -pkeyopt rsa_keygen_bits:2048
openssl genpkey -algorithm RSA -out rsa_4096_private_key.pem -pkeyopt rsa_keygen_bits:4096
openssl genpkey -algorithm RSA -out rsa_3072_private_key.pem -pkeyopt rsa_keygen_bits:3072

sha384WithRSAEncryption:
openssl genpkey -algorithm RSA -out rsa_4096_private_key.pem -pkeyopt rsa_keygen_bits:4096

sha512WithRSAEncryption:
openssl genpkey -algorithm RSA -out rsa_4096_private_key.pem -pkeyopt rsa_keygen_bits:4096

ecdsa-with-SHA256:
openssl ecparam -genkey -name prime256v1 -out ecc_private_key.pem

SM2-with-SM3:
openssl ecparam -genkey -name SM2 -out sm2_private_key.pem


2. Extract public key from private key
sha256WithRSAEncryption:
openssl pkey -in rsa_2048_private_key.pem -pubout -out rsa_2048_public_key.pem
openssl pkey -in rsa_4096_private_key.pem -pubout -out rsa_4096_public_key.pem
openssl pkey -in rsa_3072_private_key.pem -pubout -out rsa_3072_public_key.pem

sha384WithRSAEncryption:
openssl pkey -in rsa_4096_private_key.pem -pubout -out rsa_4096_public_key.pem

sha512WithRSAEncryption:
openssl pkey -in rsa_4096_private_key.pem -pubout -out rsa_4096_public_key.pem

ecdsa-with-SHA256:
openssl ec -in ecc_private_key.pem -pubout -out ecc_public_key.pem

SM2-with-SM3:
openssl ec -in sm2_private_key.pem -pubout -out sm2_public_key.pem


3. Generating a Certificate Signing Request (CSR)
sha256WithRSAEncryption:
openssl req -new -key rsa_2048_private_key.pem -out rsa_2048_csr.pem -subj "/C=CN/ST=Beijing/L=Chaoyang/O=MyCompany/CN=www.example.com"
openssl req -new -key rsa_4096_private_key.pem -out rsa_4096_csr.pem -subj "/C=CN/ST=Beijing/L=Chaoyang/O=MyCompany/CN=www.example.com"
openssl req -new -key rsa_3072_private_key.pem -out rsa_3072_csr.pem -subj "/C=CN/ST=Beijing/L=Chaoyang/O=MyCompany/CN=www.example.com"

sha384WithRSAEncryption:
openssl req -new -key rsa_4096_private_key.pem -sha384 -out rsa_4096_csr.pem -subj "/C=CN/ST=Beijing/L=Chaoyang/O=MyCompany/CN=www.example.com"

sha512WithRSAEncryption:
openssl req -new -key rsa_4096_private_key.pem -sha512 -out rsa_4096_csr.pem -subj "/C=CN/ST=Beijing/L=Chaoyang/O=MyCompany/CN=www.example.com"

ecdsa-with-SHA256:
openssl req -new -key ecc_private_key.pem -sha256 -out ecc_csr.pem -subj "/C=CN/ST=Beijing/L=Chaoyang/O=MyCompany/CN=www.example.com"

SM2-with-SM3:
openssl req -new -key sm2_private_key.pem -out sm2_csr.pem -sm3 -sigopt "distid:1234567812345678"

4. Generate self-signed certificates (valid for 365 days)
sha256WithRSAEncryption:
openssl x509 -req -days 365 -in rsa_2048_csr.pem -signkey rsa_2048_private_key.pem -out rsa_2048_certificate.pem
openssl x509 -req -days 365 -in rsa_4096_csr.pem -signkey rsa_4096_private_key.pem -out rsa_4096_certificate.pem
openssl x509 -req -days 365 -in rsa_3072_csr.pem -signkey rsa_3072_private_key.pem -out rsa_3072_certificate.pem

sha384WithRSAEncryption:
openssl x509 -req -days 365 -in rsa_4096_csr.pem -signkey rsa_4096_private_key.pem -sha384 -out rsa_4096_certificate.pem

sha512WithRSAEncryption:
openssl x509 -req -days 365 -in rsa_4096_csr.pem -signkey rsa_4096_private_key.pem -sha512 -out rsa_4096_certificate.pem

ecdsa-with-SHA256:
openssl x509 -req -days 365 -in ecc_csr.pem -signkey ecc_private_key.pem -sha256 -out ecc_certificate.pem
openssl x509 -req -days 365 -in ecc_csr.pem -signkey ecc_private_key.pem -sha256 -out ecc_certificate.pem -set_serial 10

openssl x509 -req -in intermediate.csr \
  -CA root.crt -CAkey root.key -CAcreateserial \
  -sm3 -days 1825 \
  -set_serial 12 \
  -extfile <(echo "
    basicConstraints=critical,CA:TRUE
    keyUsage=keyCertSign,cRLSign
    authorityKeyIdentifier=keyid
  ") \
  -out intermediate.crt

openssl x509 -req -in server.csr \
  -CA intermediate.crt -CAkey intermediate.key -CAcreateserial \
  -sm3 -days 365 \
  -set_serial 1 \
  -extfile <(echo "
    subjectAltName=DNS:example.com,DNS:*.example.com
    keyUsage=digitalSignature,keyEncipherment
    extendedKeyUsage=serverAuth
  ") \
  -out server.crt
  
SM2-with-SM3:
openssl x509 -req -days 365 -in ecc_csr.pem -signkey sm2_private_key.pem -sm3 -out sm2_certificate.pem
```

## Baseline-related preparations

/sys/kernel/security/ima/ascii_runtime_measurements Read the contents of this file

![输入图片说明](https://foruda.gitee.com/images/1745830028187538391/bd7d9fc9_15438102.png "屏幕截图")

Convert to json format

```
{
  "referenceValues": [
    {
		"fileName": "/init",
		"sha256": "26f5f5a706dd766158c01c7a9f4c75814a77519e9a4f7489a3cf8cf6312e8aef"
    },
	{
		"fileName": "/usr/bin/sh",
		"sha256": "836e212c2f9cbcc71abaa15fb6d5f6db8cab23fe25b2f58051c80c6bdee35cd5"
	},
	{
		"fileName": "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
		"sha256": "6c5e1b4528b704dc7081aa45b5037bda4ea9cad78ca562b4fb6b0dbdbfc7e7e7"
	},
	{
		"fileName": "/etc/ld.so.cache",
		"sha256": "3ddadedc97be05dda782d23b7636d02e7fb8ab464bae7b349187f919bd0a6c45"
	},
	{
		"fileName": "/usr/lib/x86_64-linux-gnu/libc.so.6",
		"sha256": "e7a914a33fd4f6d25057b8d48c7c5f3d55ab870ec4ee27693d6c5f3a532e6226"
	},
	{
		"fileName": "/conf/arch.conf",
		"sha256": "91f2413151b7b0451ce0b6cedc7e5919931acf792d9a26645c0deb3bc230d9fe"
	},
	{
		"fileName": "/conf/initramfs.conf",
		"sha256": "e8dd8ab00c5c23384e388bcfe98c37fc3b5ee4beaf13f1194ac8545e7695243a"
	},
	{
		"fileName": "/scripts/functions",
		"sha256": "6358cb0bc4784bb8dc13d5c9beaf65d5e88f51c9a459daeed0f1311bfc07aa96"
	},
	{
		"fileName": "/scripts/init-top/ORDER",
		"sha256": "ff8debf00a4aa65ac5d7d73c2d951cc7d2983623163ed99d20fb3a655513249b"
	},
	{
		"fileName": "/scripts/init-top/00_mount_efivarfs",
		"sha256": "67a9174870da67d416f922e94aca813a54cb5ba0c7c9e1b901b280ecaf9348c4"
	},
	{
		"fileName": "/scripts/init-top/all_generic_ide",
		"sha256": "59697cff80663c30132578d3fc6128692ff15826b4e32df3468e85db03ba3b93"
	},
	{
		"fileName": "/scripts/init-top/blacklist",
		"sha256": "50d990344cb18e8fad0d77992e68ca2c504283d578abb358ffbd90342a03ebf2"
	},
	{
		"fileName": "/scripts/init-top/udev",
		"sha256": "5893d2c4c9426b2d6166586cb5bd1852be8fa22ba2984b9e1b2ca15f8b9cca5f"
	},
  ]
}
```

Run scripts/reference_value_generate_tool.sh in the code directory to generate the ima baseline.
```bash
sh reference_value_generate_tool.sh -m ima -a sha256 -f /path/
```

Then provide the imported baseline certificate to generate jwt

Finally, import the baseline

# Agent preparation

## environmental preparation

1. The agent needs to be deployed in an openEuler environment when deploying RPM, and users can use the source code in other environments.
2. The agent can communicate with the server over the network..

## agent_config.yaml file configuration

1. The agent can configure its own IP address and port in the agent_config.yaml, and the port cannot be occupied by other processes.

For example, in the following agent_config.yaml file, port 8088 is configured by the agent, because the 8080 port is already occupied by the server.

2. Quote signing algorithm configuration:

(1) If the ak_handle is created without specifying a signing algorithm, the signature_alg in quote_signature_scheme of agent_config.yaml must be specified. The signing algorithms supported depend on the TPM chip.

(2) If the ak_handle is created with specifying signing algorithm, the signature_alg in quote_signature_scheme of agent_config.yaml must match the signing algorithm of the ak_handle.

For example, in the following agent_config.yaml file, the ak_handle with the value 0x81010020 was created using the rsapss signing algorithm, so the signature_alg in quote_signature_scheme needs to be set to rsapss.

```sh
agent:
 listen_enabled: false
 listen_address: "0.0.0.0"
 listen_port: 8088
 uuid: "a4e7c719-6b05-4ac6-b95a-7e71a9d6f9d5" 
 user_id: "test_01" 
 token_fmt: "eat"

server:
 server_url: "http://127.0.0.1:8080" 
 tls:
  cert_path: "/path/to/cert.pem"
  key_path: "/path/to/key.pem"
  ca_path: "/path/to/key.pem"

plugins:
  - name: "tpm_boot"
    path: "/usr/lib64/libtpm_boot_attester.so"
    policy_id: []
    enabled: true
    params:
      attester_type: "tpm_boot"
      tcti_config: "device" # options: device, mssim, swtpm, tabrmd, libtpm
      ak_handle: 0x81010020
      ak_nv_index: 0x150001b
      pcr_selections: 
        banks: [0, 1, 2, 3, 4, 5, 6, 7] # options: 0-23
        hash_alg: "sha256" # options: sha1, sha256, sha384, sha512, sm3
      quote_signature_scheme: # optional
        signature_alg: "rsapss" # options: rsapss, rsassa, ecdsa; The value needs to be consistent with the signing algorithm of the ak_handle.
        hash_alg: "sha256" # options: sha1, sha256, sha384, sha512, sm3
      log_file_path: "/sys/kernel/security/tpm0/binary_bios_measurements"
```

## Test Method Example

get_token：

```sh
curl -X POST http://localhost:8088/global-trust-authority/agent/v1/tokens -d '{
    "attester_info": [
      {
        "attester_type": "tpm_boot",
        "policy_ids": []
      }
    ],
    "challenge": true,
    "token_fmt": "ear",
    "attester_data": {"test_key": "test_value"}
}'

curl -X POST http://localhost:8088/global-trust-authority/agent/v1/tokens -d '{
    "attester_info": [
      {
        "attester_type": "tpm_ima",
        "policy_ids": []
      }
    ],
    "challenge": true,
    "attester_data": {"test_key": "test_value"}
}'
```

get_evidence:

```sh
curl -X POST http://localhost:8088/global-trust-authority/agent/v1/evidences \
  -H "Content-Type: application/json" \
  -d '{
    "attester_types": ["tpm_boot", "tpm_ima"],
    "nonce_type": "verifier",
    "nonce": "eyJpYXQiOjE3NTY5ODAwNjMsInZhbHVlIjoiZjMrYVc0cm1vWHUxSjNjaGlJZWNkMkJUWWYrdS84WXU0Q2VTZWYwUmt4MXYzeHJhNHZNYkNrc1locC9UaTRVWW9wN1ZvMm5XNXlsMGs4VXNQNnZrTkE9PSIsInNpZ25hdHVyZSI6Im9Mc09WbTh2OHY3ZllUTW9SZHdySjBrbWl4blFmRXIwTVliNExDa2NyZUpveUFDZmFBdlpGdmJiYURHTFJjOW9ndWkycVhMbnUwWFgvZDhEc1hhK2xwQzg2dXhSeWZtYklSdVpza2xscHd5WVV4TXlEbmFZQS9SSlFGaEtEakJjYUp0Ri9sQnpZYWMzVVNzQmFkNE5tMVE1cnBEb3RscFpHbHd5akhhdGtxUENPVzZORG9wbU9pZWtzM3RNVXpJV0NyNVZPVGhhRnpZdUdIZUZJMHdhdVdMWHY4TnlwRnlIbnllay8zdWhjdEhIc2gyRExZZUVBZW1keWQ2VnVDWmNqNjBzSjNyenF5ME9LTUFIQVRuOWhhZjk0M0k3SllDUlkvTU0xQ08rWmk1MHNTUXV1UHllVUpuTERpMGxwQmdDZmwyeWgyQ2phcU9QdE15ckhTREJwRlNNaC8xVW5xdDBlaXFzcFRESDNtNm81TXd3dUFQWGJmRFZvaDArR2dPaUowaENLUnhLY3NXSXVHNythemNoS0U3U1kyakIxWWg0NjlpSTN2MUpQRWhobnVtdC9YWENhRXBYd29aVENLRUN6NjJMYnByOWp3SzZXVVZyS2t5L3hmbkdKTlR3NWxHNGFBS1hlOFdzSldtYnpXK0Yvd0JFa0E2amdHK1hWT1J6In0=",
    "token_fmt": "ear",
    "attester_data": {"test_key": "test_value"}
  }'
```
