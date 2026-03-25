#!/bin/sh

set -eu

COOKIE="dvrtc-hc"
REQUEST="${COOKIE} d7:command4:pinge"

RESPONSE="$(printf '%s' "$REQUEST" | timeout 3 nc -u -w1 127.0.0.1 2223 2>/dev/null || true)"

[ -n "$RESPONSE" ] || exit 1
printf '%s' "$RESPONSE" | grep -q "^${COOKIE} " || exit 1
printf '%s' "$RESPONSE" | grep -q "result4:pong" || exit 1
