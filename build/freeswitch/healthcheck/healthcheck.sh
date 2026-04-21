#!/bin/sh
set -eu

OUTPUT="$(timeout 20 fs_cli -H 127.0.0.1 -P 8021 -p ClueCon -x status 2>&1 || true)"
printf '%s\n' "$OUTPUT" | grep -Eq 'UP|FreeSWITCH'
