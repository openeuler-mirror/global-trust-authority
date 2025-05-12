#!/bin/bash
operator="key_manager"
algorithm=$1
encoding="pem"
version=$2

set -e

export BAO_ADDR=http://127.0.0.1:8200/
export BAO_TOKEN=

validate_input() {
    if [ $# -ne 2 ]; then
        echo "用法: $0 <algorithm> <version>" >&2
        echo "支持的算法: rsa_3072, sm2, ec" >&2
        exit 1
    fi

    if ! [[ "$version" =~ ^[0-9]+$ ]] || [ "$version" -lt 1 ]; then
        echo "版本必须是大于0的整数" >&2
        exit 1
    fi

    case "$algorithm" in
        rsa_3072|sm2|ec) ;;
        *)
            echo "不支持的算法: $algorithm" >&2
            echo "支持的算法: rsa_3072, sm2, ec" >&2
            exit 1
            ;;
    esac
}

generate_key() {
    local algorithm=$1
    local key_content

    case "$algorithm" in
        rsa_3072)
            # RSA-PSS 3072 (OpenSSL 3.0+ 需要指定 PSS 参数)
            openssl genpkey -algorithm RSA-PSS \
                -pkeyopt rsa_keygen_bits:3072 \
                -pkeyopt rsa_pss_keygen_md:sha256 \
                -pkeyopt rsa_pss_keygen_mgf1_md:sha256 \
                -pkeyopt rsa_pss_keygen_saltlen:-1 \
                2>/dev/null
            ;;
        sm2)
            # SM2 (需 OpenSSL 支持 SM2)
            openssl genpkey -algorithm SM2 2>/dev/null
            ;;
        ec)
            # EC (P-256 曲线)
            openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 2>/dev/null
            ;;
        *)
            echo "不支持的算法: $algorithm" >&2
            exit 1
            ;;
    esac
}

if [ $# -ne 2 ]; then
    echo "用法: $0 <algorithm> <version>" >&2
    echo "支持的算法: rsa_3072, sm2, ec" >&2
    exit 1
fi

validate_input "$@"

for ((i=1; i<=version; i++)); do
# 生成密钥并写入临时文件
    nsk=$(generate_key "$algorithm")
    nsk_file=$(mktemp /tmp/nsk_XXXXXX.pem)
    echo "$nsk" > "$nsk_file"

    fsk=$(generate_key "$algorithm")
    fsk_file=$(mktemp /tmp/fsk_XXXXXX.pem)
    echo "$fsk" > "$fsk_file"

    tsk=$(generate_key "$algorithm")
    tsk_file=$(mktemp /tmp/tsk_XXXXXX.pem)
    echo "$tsk" > "$tsk_file"
    ./key_manager put --key_name NSK --algorithm ${algorithm} --encoding pem --key_file ${nsk_file}
    ./key_manager put --key_name FSK --algorithm ${algorithm} --encoding pem --key_file ${fsk_file}
    ./key_manager put --key_name TSK --algorithm ${algorithm} --encoding pem --key_file ${tsk_file}
    rm -f "$nsk_file" "$fsk_file" "$tsk_file"
done

echo "生成成功"