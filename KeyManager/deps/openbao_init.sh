#!/bin/bash
set -e

# 启动 OpenBao
nohup /usr/bin/bao server -config=/opt/key_manager/deps/openbao.hcl >/var/log/openbao.log 2>&1 &
export BAO_ADDR='http://127.0.0.1:8200'

# 等待服务就绪
sleep 10

# 检查密封状态
sealed=$(bao status | awk '/Sealed/ {print $2}')
if [ "$sealed" = "true" ] && [ ! -f /opt/key_manager/bao_init_data.txt ]; then
    echo "正在初始化 OpenBao..."
    bao operator init > /opt/key_manager/bao_init_data.txt
    chmod 600 /opt/key_manager/bao_init_data.txt

    ROOT_TOKEN=$(grep "Initial Root Token:" /opt/key_manager/bao_init_data.txt | awk '{print $4}')
    UNSEAL_KEYS=($(grep "Unseal Key [1-5]:" /opt/key_manager/bao_init_data.txt | awk '{print $4}'))

    # 解封当前openbao
    bao operator unseal "${UNSEAL_KEYS[0]}"
    bao operator unseal "${UNSEAL_KEYS[1]}"
    bao operator unseal "${UNSEAL_KEYS[2]}"
fi

echo "OpenBao 已就绪"

cd /opt/key_manager/

awk -v token="$ROOT_TOKEN" -v addr="http://127.0.0.1:8200/" '
BEGIN { FS=OFS="=" }  # 输入/输出分隔符均为 =
{
  if ($1 == "KEY_MANAGER_ROOT_TOKEN") $2 = token
  if ($1 == "KEY_MANAGER_SECRET_ADDR") $2 = addr
  print
}
' .env > .env.tmp && mv .env.tmp .env

./key_managerd
