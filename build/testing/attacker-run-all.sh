#!/bin/sh
set -eu

TARGET_INPUT="${1:-${PUBLIC_IPV4:-}}"
TARGET_MYSQL_PORT="${2:-${MYSQL_PORT:-23306}}"
SCENARIO="${SCENARIO:-pbx1}"

if [ -z "${TARGET_INPUT}" ]; then
    echo "usage: attacker-run-all <target-ip> [mysql-port]" >&2
    echo "or set PUBLIC_IPV4 in the environment" >&2
    exit 2
fi

exec env \
    SCENARIO="${SCENARIO}" \
    RUN_CALLGEN_CHECK=0 \
    RUN_DIGESTLEAK_REG_CHECK=0 \
    RUN_DIGESTLEAK_AUTH_CHECK=0 \
    RUN_DIGESTLEAK_PUBLIC_BLOCK_CHECK=1 \
    testing-run-all "${TARGET_INPUT}" "${TARGET_MYSQL_PORT}"
