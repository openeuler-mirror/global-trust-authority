#!/bin/bash
set -e

# 启动 OpenBao
export BAO_ADDR='http://127.0.0.1:8200'
if ps aux | grep -q "[b]ao server.*openbao.hcl"; then
    echo "OpenBao 服务已在运行，跳过启动"
else
    echo "启动 OpenBao..."
    nohup /usr/bin/bao server -config=/opt/key_manager/deps/openbao.hcl >/var/log/openbao.log 2>&1 &

    # 等待服务就绪
    sleep 10
fi

sealed=$(bao status | awk '/Sealed/ {print $2}')
if [ "$sealed" = "true" ]; then
    echo "OpenBao 处于密封状态，正在解封..."

    if [ ! -f /opt/key_manager/bao_init_data.txt ]; then
        bao operator init > /opt/key_manager/bao_init_data.txt
        chmod 600 /opt/key_manager/bao_init_data.txt
    fi

    # 从文件中读取解封密钥
    UNSEAL_KEYS=($(grep "Unseal Key [1-5]:" /opt/key_manager/bao_init_data.txt | awk '{print $4}'))

    # 执行解封（假设需要3个密钥）
    bao operator unseal "${UNSEAL_KEYS[0]}"
    bao operator unseal "${UNSEAL_KEYS[1]}"
    bao operator unseal "${UNSEAL_KEYS[2]}"

    echo "OpenBao 解封完成"
else
    echo "OpenBao 已解封，无需操作"
fi

echo "OpenBao 已就绪"

# 更新 .env 文件（仅在需要时）
if [ -f /opt/key_manager/bao_init_data.txt ] && [ -f /opt/key_manager/.env ]; then
    echo "更新 .env 文件..."
    ROOT_TOKEN=$(grep "Initial Root Token:" /opt/key_manager/bao_init_data.txt | awk '{print $4}')

    awk -v token="$ROOT_TOKEN" -v addr="http://127.0.0.1:8200/" '
    BEGIN { FS=OFS="=" }
    {
      if ($1 == "KEY_MANAGER_ROOT_TOKEN") $2 = token
      if ($1 == "KEY_MANAGER_SECRET_ADDR") $2 = addr
      print
    }
    ' /opt/key_manager/.env > /opt/key_manager/.env.tmp && mv /opt/key_manager/.env.tmp /opt/key_manager/.env
fi

cd /opt/key_manager/
./key_managerd
