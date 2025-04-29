#!/bin/bash
mkdir -p /home/hisec/joint_debugging/cert/KeyManager

# 生成 KeyManager 的根CA（不变）
openssl genrsa -out /home/hisec/joint_debugging/cert/KeyManager/KM_key.pem 2048
openssl req -x509 -new -nodes -key \
  /home/hisec/joint_debugging/cert/KeyManager/KM_key.pem \
  -out /home/hisec/joint_debugging/cert/KeyManager/KM_cert.pem \
  -days 3650 -subj "/CN=RootCA-KeyManager"

# 生成 KeyManager 服务端证书（新增！）
openssl genrsa -out /home/hisec/joint_debugging/cert/KeyManager/key_manager_server_key.pem 2048
openssl req -new -key /home/hisec/joint_debugging/cert/KeyManager/key_manager_server_key.pem \
  -out /home/hisec/joint_debugging/cert/KeyManager/key_manager_server.csr \
  -subj "/CN=key_manager" \
  -addext "subjectAltName = DNS:key_manager"  # 关键：添加 SAN 扩展

openssl x509 -req -in /home/hisec/joint_debugging/cert/KeyManager/key_manager_server.csr \
  -CA /home/hisec/joint_debugging/cert/KeyManager/KM_cert.pem \
  -CAkey /home/hisec/joint_debugging/cert/KeyManager/KM_key.pem \
  -CAcreateserial \
  -out /home/hisec/joint_debugging/cert/KeyManager/key_manager_server_cert.pem \
  -days 365 -sha256 \
  -extfile <(echo "subjectAltName = DNS:key_manager")  # 再次确认 SAN

# 生成 RA 客户端证书（保持不变）
openssl genrsa -out /home/hisec/joint_debugging/cert/KeyManager/RA_client_key.pem 2048
openssl req -new -key /home/hisec/joint_debugging/cert/KeyManager/RA_client_key.pem \
  -out /home/hisec/joint_debugging/cert/KeyManager/RA_client.csr \
  -subj "/CN=RA-Service"
openssl x509 -req -in /home/hisec/joint_debugging/cert/KeyManager/RA_client.csr \
  -CA /home/hisec/joint_debugging/cert/KeyManager/KM_cert.pem \
  -CAkey /home/hisec/joint_debugging/cert/KeyManager/KM_key.pem \
  -CAcreateserial \
  -out /home/hisec/joint_debugging/cert/KeyManager/RA_client_cert.pem \
  -days 365 -sha256 -extfile <(echo "extendedKeyUsage = clientAuth")

# 验证证书
openssl verify -CAfile /home/hisec/joint_debugging/cert/KeyManager/KM_cert.pem \
  /home/hisec/joint_debugging/cert/KeyManager/key_manager_server_cert.pem

echo "证书生成完成！"