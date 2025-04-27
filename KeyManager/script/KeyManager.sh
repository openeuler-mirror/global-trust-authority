#!/bin/bash
# KeyManager证书链
# 创建证书目录
mkdir -p /home/hisec/joint_debugging/cert/KeyManager
# 生成 KeyManager 的根CA
openssl genrsa -out /home/hisec/joint_debugging/cert/KeyManager/KM_key.pem 2048
openssl req -x509 -new -nodes -key \
/home/hisec/joint_debugging/cert/KeyManager/KM_key.pem \
-out /home/hisec/joint_debugging/cert/KeyManager/KM_cert.pem \
-days 3650 \
-subj "/CN=RootCA-KeyManager"
# 为 RA 生成客户端证书
openssl genrsa -out /home/hisec/joint_debugging/cert/KeyManager/RA_client_key.pem 2048
openssl req -new -key /home/hisec/joint_debugging/cert/KeyManager/RA_client_key.pem \
-out /home/hisec/joint_debugging/cert/KeyManager/RA_client.csr \
-subj "/CN=RA-Service"
openssl x509 -req -in /home/hisec/joint_debugging/cert/KeyManager/RA_client.csr \
-CA /home/hisec/joint_debugging/cert/KeyManager/KM_cert.pem \
-CAkey /home/hisec/joint_debugging/cert/KeyManager/KM_key.pem \
-CAcreateserial \
-out /home/hisec/joint_debugging/cert/KeyManager/RA_client_cert.pem \
-days 365 -sha256 \
-extfile <(echo "extendedKeyUsage = clientAuth")
# 验证证书
openssl verify -CAfile /home/hisec/joint_debugging/cert/KeyManager/KM_cert.pem \
/home/hisec/joint_debugging/cert/KeyManager/RA_client_cert.pem
# 创建双向验证所需的证书链
cat /home/hisec/joint_debugging/cert/KeyManager/RA_client_cert.pem \
/home/hisec/joint_debugging/cert/KeyManager/KM_cert.pem > \
/home/hisec/joint_debugging/cert/KeyManager/RA_client_cert_chain.pem
echo "证书生成完成，保存在 /home/hisec/joint_debugging/cert/KeyManager 目录"
