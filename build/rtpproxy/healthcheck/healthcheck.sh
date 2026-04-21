#!/bin/sh
set -eu

COOKIE="dvrtc-hc"
REQUEST="${COOKIE} V"
RESPONSE="$(printf '%s\n' "$REQUEST" | timeout 3 nc -u -w1 127.0.0.1 7722 2>/dev/null || true)"

grep -q '^rtpproxy$' /proc/1/comm
[ -n "$RESPONSE" ] || exit 1
printf '%s' "$RESPONSE" | grep -q "^${COOKIE} " || exit 1
