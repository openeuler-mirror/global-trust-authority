#!/bin/bash

set -e
readonly VERSION="0.1.0"
# 标准化路径声明
readonly CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="$(realpath "${CURRENT_DIR}/../")"
readonly SPEC_FILE="${PROJECT_DIR}/script/key_manager.spec"

# 清理旧构建
clean_old_build() {
    echo "[Clean] Remove the historical build files..."
    rm -fv ~/rpmbuild/SOURCES/key_manager-*.tar.gz
    find ~/rpmbuild/RPMS -name "key_manager-*.rpm" -exec rm -fv {} \;
}

# 生成源码压缩包
create_source_tar_file() {
    local -r tar_file="${HOME}/rpmbuild/SOURCES/key_manager-${VERSION}.tar.gz"
    (
        shopt -s dotglob  # 包含隐藏文件（如 .env）
        cd "${PROJECT_DIR}" || exit 1
        tar czf "${tar_file}" \
            --exclude=target \
            --exclude=Cargo.lock \
            --transform "s,^,key_manager-${VERSION}/," \
            *
    )
    echo "[Packaging] The source code compressed package has been generated: ${tar_file}"
}

# RPM 构建流程
build_rpm() {
    echo "[Build] Start RPM compilation..."
    (
        cd ~/rpmbuild/SPECS || { echo "Error: Unable to access the SPECS directory"; exit 1; }
        rpmbuild -bb --clean "${SPEC_FILE}" --define "_version ${VERSION}"
    )

    local -r rpm_path=$(ls ~/rpmbuild/RPMS/x86_64/key_manager*.rpm 2>/dev/null)
    if [[ -f "${rpm_path}" ]]; then
        echo "[Result] RPM package path: ${rpm_path}"
    else
        echo "Error: The generated RPM package was not found"
        exit 1
    fi
}

main() {
    clean_old_build
    create_source_tar_file
    build_rpm
}

main "$@"