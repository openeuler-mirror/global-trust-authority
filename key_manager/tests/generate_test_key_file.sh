#!/bin/bash

# 创建测试数据目录
TESTDATA_DIR="$(dirname "$0")/testdata"
mkdir -p "$TESTDATA_DIR"

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
                -out "$TESTDATA_DIR/rsa_3072.key" \
                2>/dev/null
            ;;
        sm2)
            # SM2 (需 OpenSSL 支持 SM2)
            openssl genpkey -algorithm EC \
                -pkeyopt ec_paramgen_curve:SM2 \
                -pkeyopt ec_param_enc:named_curve \
                -out "$TESTDATA_DIR/sm2.key" 2>/dev/null
            ;;
        ec)
            # EC (P-256 曲线)
            openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$TESTDATA_DIR/ec.key" 2>/dev/null
            ;;
        *)
            echo "不支持的算法: $algorithm" >&2
            exit 1
            ;;
    esac
}

main() {
    generate_key "rsa_3072"
    generate_key "sm2"
    generate_key "ec"
    echo "abcdefg" > "$TESTDATA_DIR/invalid.key"
    echo -e "\nAll keys saved to: $TESTDATA_DIR"
}

main "$@"