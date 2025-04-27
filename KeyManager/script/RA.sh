#!/bin/bash
# RA证书链
# 创建证书目录
mkdir -p /home/hisec/joint_debugging/cert/RA
# 生成 RA 的根CA
openssl genrsa -out /home/hisec/joint_debugging/cert/RA/RA_key.pem 2048
openssl req -x509 -new -nodes -key /home/hisec/joint_debugging/cert/RA/RA_key.pem \
-out /home/hisec/joint_debugging/cert/RA/RA_cert.pem \
-days 3650 \
-subj "/CN=RootCA-RA"
# 为 KeyManager 生成证书
openssl genrsa -out /home/hisec/joint_debugging/cert/RA/KeyManager_client_key.pem 2048
openssl req -new -key /home/hisec/joint_debugging/cert/RA/KeyManager_client_key.pem \
-out /home/hisec/joint_debugging/cert/RA/KeyManager_client.csr \
-subj "/CN=KeyManager-Service"
openssl x509 -req -in /home/hisec/joint_debugging/cert/RA/KeyManager_client.csr \
-CA /home/hisec/joint_debugging/cert/RA/RA_cert.pem \
-CAkey /home/hisec/joint_debugging/cert/RA/RA_key.pem \
-CAcreateserial \
-out /home/hisec/joint_debugging/cert/RA/KeyManager_client_cert.pem \
-days 365 -sha256 \
-extfile <(echo -e "extendedKeyUsage = serverAuth")
# 验证证书
openssl verify -CAfile /home/hisec/joint_debugging/cert/RA/RA_cert.pem \
/home/hisec/joint_debugging/cert/RA/KeyManager_client_cert.pem
echo "证书生成完成，保存在 /home/hisec/joint_debugging/cert/RA 目录"