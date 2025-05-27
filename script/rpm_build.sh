#!/bin/bash
set -e

CURRENT_DIR="$(cd "$(dirname "$0")"; pwd)"
ROOT_DIR="$(cd "${CURRENT_DIR}/../"; pwd)"
RPM_SOURCE_DIR="$HOME/rpmbuild/SOURCES"
RPM_SPEC_DIR="$HOME/rpmbuild/SPECS"
SOURCE_DIR_NAME=$(basename ${ROOT_DIR})

VERSION=$(grep "^version:" "${ROOT_DIR}/config/common.yaml" | awk '{print $2}')
RELEASE=$(grep "^release:" "${ROOT_DIR}/config/common.yaml" | awk '{print $2}')

ENABLE_AGENT_RPM=false
ENABLE_SERVER_RPM=false
ENABLE_CLI_RPM=false

show_help() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -a    Build agent RPM package"
    echo "  -s    Build server RPM package"
    echo "  -c    Build cli RPM package"
    echo "  -h    Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 -a -c    # Build agent and cli RPM packages"
    echo "  $0 -s       # Build server RPM package only"
}

while getopts "asch" opt; do
    case $opt in
        a) ENABLE_AGENT_RPM=true ;;
        s) ENABLE_SERVER_RPM=true ;;
        c) ENABLE_CLI_RPM=true ;;
        h) show_help; exit 0 ;;
        ?) show_help; exit 1 ;;
    esac
done

if [ "$ENABLE_AGENT_RPM" = false ] && [ "$ENABLE_SERVER_RPM" = false ] && [ "$ENABLE_CLI_RPM" = false ]; then
    echo "Error: Please specify at least one RPM package type to build"
    show_help
    exit 1
fi

if [ ! -d $RPM_SOURCE_DIR ]; then
    mkdir -p $RPM_SOURCE_DIR
fi

if [ ! -d $RPM_SPEC_DIR ]; then
    mkdir -p $RPM_SPEC_DIR
fi

rm -rf $RPM_SOURCE_DIR/*
cd ${ROOT_DIR}
cargo clean
cd ..
tar -zcf ${SOURCE_DIR_NAME}.tar.gz ${SOURCE_DIR_NAME}
mv ${SOURCE_DIR_NAME}.tar.gz $RPM_SOURCE_DIR

cd ${SOURCE_DIR_NAME}
cargo vendor --respect-source-config
tar -zcf vendor.tar.gz vendor
mv vendor.tar.gz $RPM_SOURCE_DIR

rm -rf $RPM_SPEC_DIR/*
cd ./script
if [ "$ENABLE_AGENT_RPM" = true ]; then
    cp agent.spec $RPM_SPEC_DIR
    rpmbuild -bb --clean $RPM_SPEC_DIR/agent.spec --define "_ra_version ${VERSION}" --define "_ra_release ${RELEASE}" --define "_source_dir ${SOURCE_DIR_NAME}"
fi

if [ "$ENABLE_SERVER_RPM" = true ]; then
    mkdir -p /etc/attestation_server/certs && \
        openssl req -x509 -newkey rsa:4096 -nodes \
            -keyout /etc/attestation_server/certs/key.pem \
            -out /etc/attestation_server/certs/cert.pem \
            -days 365 \
            -subj "/CN=127.0.0.1"
    chmod 700 /etc/attestation_server/certs
    chmod 600 /etc/attestation_server/certs/*
    cp server.spec $RPM_SPEC_DIR
    rpmbuild -bb --clean $RPM_SPEC_DIR/server.spec --define "_ra_version ${VERSION}" --define "_ra_release ${RELEASE}"
fi

if [ "$ENABLE_CLI_RPM" = true ]; then
    cp cli.spec $RPM_SPEC_DIR
    rpmbuild -bb --clean $RPM_SPEC_DIR/cli.spec --define "_ra_version ${VERSION}" --define "_ra_release ${RELEASE}" --define "_source_dir ${SOURCE_DIR_NAME}"
fi
