#!/bin/bash
operator="key_manager"
algorithm=$1
encoding="pem"
version=$2

export BAO_ADDR=http://127.0.0.1:8200/
export BAO_TOKEN=

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
                -pkeyopt rsa_pss_keygen_saltlen:32 \
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

for ((i=1; i<=version; i++)); do
    nsk=$(generate_key "$algorithm")
    bao kv put -mount="${operator}" NSK private_key="${nsk}" algorithm="${algorithm}" encoding="${encoding}"
    fsk=$(generate_key "$algorithm")
    bao kv put -mount="${operator}" FSK private_key="${nsk}" algorithm="${algorithm}" encoding="${encoding}"
    ask=$(generate_key "$algorithm")
    bao kv put -mount="${operator}" TSK private_key="${nsk}" algorithm="${algorithm}" encoding="${encoding}"
done

echo "生成成功"