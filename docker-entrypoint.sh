#!/bin/sh
set -e

chmod -R 550 /var/test_docker/app
find /var/test_docker/app -type f -exec chmod 550 {} \;
find /var/test_docker/app -type d -exec chmod 550 {} \;

exec "$@"