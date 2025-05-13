# Server准备
## 策略相关数据准备

新增tpm_boot策略和tpm_ima策略

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

# Extract is_log_valid from first TcgEventLog log
is_log_valid = valid {
    some i
    logs := input.evidence.logs
    logs[i].log_type == "TcgEventLog"
    valid := logs[i].is_log_valid
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
    is_log_valid == true
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

# Extract is_log_valid from first tpm_ima log
is_log_valid = valid {
    some i
    logs := input.evidence.logs
    logs[i].log_type == "ImaLog"
    valid := logs[i].is_log_valid
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
    is_log_valid == true
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

## 证书相关的准备

### 导入插件的ak证书

查看agent侧生成ak根证书的方法，然后调用新增证书接口进行证书新增

### 导入基线和策略的证书

此处自己生成证书即可

```
1、生成私钥
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


2、从私钥提取公钥
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


3. 生成证书签名请求 (CSR)
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

4、生成自签名证书 (有效期365天)
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

## 基线相关的准备

/sys/kernel/security/ima/ascii_runtime_measurements 读取此份文件中的内容

![输入图片说明](https://foruda.gitee.com/images/1745830028187538391/bd7d9fc9_15438102.png "屏幕截图")

转换成json格式

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

```
#!/bin/bash

# 输出文件名
OUTPUT_FILE="ima_measurements.json"

# 检查文件是否存在
if [ ! -f "/sys/kernel/security/ima/ascii_runtime_measurements" ]; then
    echo "Error: /sys/kernel/security/ima/ascii_runtime_measurements not found." >&2
    exit 1
fi

# 检查是否有读取权限
if [ ! -r "/sys/kernel/security/ima/ascii_runtime_measurements" ]; then
    echo "Error: No permission to read /sys/kernel/security/ima/ascii_runtime_measurements." >&2
    exit 1
fi

# 处理文件并输出到JSON
{
awk 'BEGIN {
    print "{"
    print "  \"referenceValues\": ["
    first=1
}
/ima-ng sha256:/ {  # 只处理包含"ima-ng sha256:"的行
    # 提取sha256（第4个字段，去掉"sha256:"前缀）
    sha256 = substr($4, 8)
    # 文件名是第5个字段及之后（处理可能包含空格的文件名）
    filename = $5
    for (i=6; i<=NF; i++) {
        filename = filename " " $i
    }
    
    if (!first) {
        print "    },"
    } else {
        first=0
    }
    
    printf "    {\n"
    printf "      \"fileName\": \"%s\",\n", filename
    printf "      \"sha256\": \"%s\"\n", sha256
}
END {
    if (!first) {  # 只有当有数据时才输出闭合部分
        print "    }"
    }
    print "  ]"
    print "}"
}' /sys/kernel/security/ima/ascii_runtime_measurements
} > "$OUTPUT_FILE"

# 检查输出是否成功
if [ $? -eq 0 ]; then
    echo "Successfully saved IMA measurements to $OUTPUT_FILE"
else
    echo "Error: Failed to save IMA measurements" >&2
    exit 1
fi

# 设置适当的文件权限
chmod 644 "$OUTPUT_FILE"

```

再提供导入的基线证书生成jwt

最后导入基线




# Agent准备
# 一、环境

1、Agent需要部署在有TPM芯片（或者swtpm，需要有/dev/tpm0设备节点、tpm_boot的日志路径/sys/kernel/security/tpm0/binary_bios_measurements和tpm_ima的日志路径/sys/kernel/security/ima/ascii_runtime_measurements）的openEuler环境；

2、Agent和Server需要部署在同个网段，能互相ping通。

# 二、使用自签名CA签发AK证书：

1、执行以下命令创建ak之前请使用tpm2-tools工具验证要使用的nv index和ak密钥是否存在，如果存在请删除：

tpm_tools相关命令

```sh
# 1.删除nv 
sudo tpm2_nvundefine 0x150001b

# 2.删除ak密钥
sudo tpm2_evictcontrol -C o -c 0x81010020

# 3.查看证书nv_index是否存在
sudo tpm2_getcap handles-nv-index

# 4.查看ak密钥是否存在
sudo tpm2_getcap handles-persistent

# 5.查看ak public
sudo tpm2_readpublic -c 0x81010020

```

2、确保使用的nv index和ak密钥不存在后，执行以下命令使用自签名CA签发AK证书

```sh
# 1.创建ak及持久化
sudo tpm2_createek -c ek.handle -G rsa -u ek.pub
sudo tpm2_createak -C ek.handle -c ak.ctx -u ak.pub -n ak.name
sudo tpm2_evictcontrol -C o -c ak.ctx 0x81010020

# 2.读取pem格式ak公钥
sudo tpm2_readpublic -c 0x81010020 -o ak.pem -f pem -Q

# 3.创建根CA密钥及根CA证书
openssl genrsa -out rootCA.key 2048
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 10950 -out rootCA.crt -subj "/C=CN/O=test CA/OU=test/CN=TPM Root CA v2"

# 4.生成CSR
# 1) 创建正确格式的配置文件
cat > cert.conf << EOF
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
CN = TPM AK
O = My Organization
C = CN

[ v3_req ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth, serverAuth
EOF

# 2) 创建CSR
openssl req -new -key rootCA.key -out temp.csr -config cert.conf

# 3) 签发证书 使用CA签署，强制使用TPM公钥
sudo openssl x509 -req -in temp.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -days 3650 -out ak.crt -force_pubkey ak.pem

# 5. 查看证书
openssl x509 -in ak.crt -noout -text

# 6. 转der证书
openssl x509 -in ak.crt -inform PEM -out ak.der -outform DER

# 7. 证书写tpm nv index
# 1) 查看证书大小
ll ak.der

# 2) 创建NVRAM空间： -s 传入ak.cer的大小， 0x150001b是即将写入证书的nv_index
sudo tpm2_nvdefine -C o -s 778 0x150001b -a "ppread|ppwrite|authread|ownerread|ownerwrite"

# 3) 写入证书数据
sudo tpm2_nvwrite -C o 0x150001b -i ak.der

# 4). 验证写入是否成功
sudo tpm2_nvread 0x150001b > ak_read.der
```

执行完毕后，将生成的rootCA.crt发给Serevr测试人员，导入Server侧。

备注：Server侧导入的rootCA.crt的CN名字（上面步骤3中的CN字段内容）需要唯一，即Server侧不能有两本CN名字一样的rootCA.crt，不然Server侧证据校验时证书链会校验失败。

# 三、agent_config.yaml文件配置：

Agent和Server的ip和端口可在agent_config.yaml文件中配置，各自端口不能被其他进程占用。

例如 如下的agent_config.yaml，8088端口只被Agent占用监听，8080端口被Server占用监听：

```sh
agent:
 listen_address: "0.0.0.0"
 listen_port: 8088
 uuid: "TPM AK"  # 唯一的 agent 标识符
 user_id: "test_lyz" # Unique user identifier

server:
 server_url: "http://10.10.0.102:8080"  # 基础URL，API路径将自动添加
 tls:
  cert_path: "/path/to/cert.pem"
  key_path: "/path/to/key.pem"
  ca_path: "/path/to/key.pem"
```

# 四、测试方法示例：

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
    "attester_data": "test_data"
}'

curl -X POST http://localhost:8088/global-trust-authority/agent/v1/tokens -d '{
    "attester_info": [
      {
        "attester_type": "tpm_ima",
        "policy_ids": []
      }
    ],
    "challenge": true,
    "attester_data": "test_data"
}'
```

get_evidence:

```sh
curl -X POST http://localhost:8088/global-trust-authority/agent/v1/evidences \
  -H "Content-Type: application/json" \
  -d '{
    "attester_types": ["tpm_boot", "tpm_ima"],
    "nonce_type": "default",
    "nonce": {
      "iat": 123456789,
      "value": "5J7Q3sQbF6Yp6R6T1Qm8k1gX7j9YzvH4l6eQ2J1s8x0a9vT3h2K5z8W0u4x9V7n2b1c6e3w0p8m7u5q9t4r3y2z0v1s6d8a5g",
      "signature": "Y0t2bGxwR1F6dGJmU1l4N3lBUXk2T2JZc3h5T0l6Z3Z4d2lQd2F6R0ZyZ3l6Z2V4V2V5d2F0Y3l6a2N6d2p6d2x5d2V6d2s="
    },
    "attester_data": "custom_data"
  }'
```
