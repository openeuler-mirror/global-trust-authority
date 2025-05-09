#!/bin/bash
set -euo pipefail  # 启用严格模式，遇到错误自动退出

# 显示用法说明
usage() {
    echo "用法: $0 -p <证书生成路径>"
    echo "必须选项:"
    echo "  -p, --path <路径>    指定证书生成路径（必须存在且可写）"
    echo "  -h, --help           显示帮助信息"
    exit 1
}

# 解析命令行参数
CERT_DIR=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--path)
            CERT_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "错误: 未知选项 $1" >&2
            usage
            ;;
    esac
done

# 验证路径参数
validate_path() {
    if [ -z "$CERT_DIR" ]; then
        echo "错误: 必须使用 -p 参数指定证书生成路径" >&2
        usage
    fi

    if ! [ -d "$CERT_DIR" ]; then
        echo "错误: 指定路径不存在: $CERT_DIR" >&2
        exit 1
    fi

    if ! [ -w "$CERT_DIR" ]; then
        echo "错误: 指定路径不可写: $CERT_DIR" >&2
        exit 1
    fi

    echo "证书将生成到: $CERT_DIR"
}

# 生成证书函数
generate_certs() {
    local cert_dir="$1"

    echo "=== 生成根CA证书 ==="
    openssl genrsa -out "$cert_dir/km_key.pem" 2048 || {
        echo "生成根CA私钥失败" >&2; exit 1
    }

    openssl req -x509 -new -nodes -key "$cert_dir/km_key.pem" \
        -out "$cert_dir/km_cert.pem" \
        -days 3650 -subj "/CN=RootCA-KeyManager" || {
        echo "生成根CA证书失败" >&2; exit 1
    }

    echo "=== 生成服务端证书 ==="
    openssl genrsa -out "$cert_dir/key_manager_server_key.pem" 2048 || {
        echo "生成服务端私钥失败" >&2; exit 1
    }

    openssl req -new -key "$cert_dir/key_manager_server_key.pem" \
        -out "$cert_dir/key_manager_server.csr" \
        -subj "/CN=key_manager" \
        -addext "subjectAltName = DNS:key_manager" || {
        echo "生成服务端CSR失败" >&2; exit 1
    }

    openssl x509 -req -in "$cert_dir/key_manager_server.csr" \
        -CA "$cert_dir/km_cert.pem" \
        -CAkey "$cert_dir/km_key.pem" \
        -CAcreateserial \
        -out "$cert_dir/key_manager_server_cert.pem" \
        -days 365 -sha256 \
        -extfile <(echo "subjectAltName = DNS:key_manager") || {
        echo "签发服务端证书失败" >&2; exit 1
    }

    echo "=== 生成RA客户端证书 ==="
    openssl genrsa -out "$cert_dir/ra_client_key.pem" 2048 || {
        echo "生成客户端私钥失败" >&2; exit 1
    }

    openssl req -new -key "$cert_dir/ra_client_key.pem" \
        -out "$cert_dir/ra_client.csr" \
        -subj "/CN=RA-Service" || {
        echo "生成客户端CSR失败" >&2; exit 1
    }

    openssl x509 -req -in "$cert_dir/ra_client.csr" \
        -CA "$cert_dir/km_cert.pem" \
        -CAkey "$cert_dir/km_key.pem" \
        -CAcreateserial \
        -out "$cert_dir/ra_client_cert.pem" \
        -days 365 -sha256 -extfile <(echo "extendedKeyUsage = clientAuth") || {
        echo "签发客户端证书失败" >&2; exit 1
    }

    echo "=== 验证证书 ==="
    if ! openssl verify -CAfile "$cert_dir/km_cert.pem" \
        "$cert_dir/key_manager_server_cert.pem" >/dev/null; then
        echo "服务端证书验证失败" >&2
        exit 1
    fi

    if ! openssl verify -CAfile "$cert_dir/km_cert.pem" \
        "$cert_dir/ra_client_cert.pem" >/dev/null; then
        echo "客户端证书验证失败" >&2
        exit 1
    fi
}

# 主函数
main() {
    validate_path
    generate_certs "$CERT_DIR"

    echo ""
    echo "证书生成完成！"
    echo "生成的证书位于: $CERT_DIR"
    echo "文件列表:"
    ls -l "$CERT_DIR"/*.pem "$CERT_DIR"/*.csr 2>/dev/null | awk '{print $9}'
}

main