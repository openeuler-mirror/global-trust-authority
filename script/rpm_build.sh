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

while getopts "as" opt; do
    case $opt in
        a) ENABLE_AGENT_RPM=true ;;
        s) ENABLE_SERVER_RPM=true ;;
    esac
done

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
cargo vendor
tar -zcf vendor.tar.gz vendor
mv vendor.tar.gz $RPM_SOURCE_DIR

rm -rf $RPM_SPEC_DIR/*
cd ./script
if [ "$ENABLE_AGENT_RPM" = true ]; then
    cp agent.spec $RPM_SPEC_DIR
    rpmbuild -bb --clean $RPM_SPEC_DIR/agent.spec --define "_ra_version ${VERSION}" --define "_ra_release ${RELEASE}" --define "_source_dir ${SOURCE_DIR_NAME}"
fi

if [ "$ENABLE_SERVER_RPM" = true ]; then
    cp server.spec $RPM_SPEC_DIR
    rpmbuild -bb --clean $RPM_SPEC_DIR/server.spec --define "_ra_version ${VERSION}" --define "_ra_release ${RELEASE}"
fi
