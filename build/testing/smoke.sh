#!/bin/sh
set -eu

TARGET_IP="${1:-127.0.0.1}"
SMOKE_EXT="${2:-1000}"
TARGET_MYSQL_PORT="${3:-${MYSQL_PORT:-23306}}"
SCENARIO="${SCENARIO:-pbx1}"

python3 /opt/testing/scripts/dvrtc-checks.py \
    smoke \
    --scenario "${SCENARIO}" \
    --host "${TARGET_IP}" \
    --extension "${SMOKE_EXT}" \
    --mysql-port "${TARGET_MYSQL_PORT}"
