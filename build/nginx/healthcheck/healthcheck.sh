#!/bin/sh

set -eu

check_url() {
    URL="$1"
    shift
    BODY="$(curl -gfsS --connect-timeout 2 --max-time 5 "$@" "$URL")" || return 1
    [ "$BODY" = "ok" ]
}

nginx -t >/dev/null 2>&1

check_url "http://127.0.0.1/healthz"
check_url "https://127.0.0.1/healthz" -k

if [ -n "${PUBLIC_IPV6:-}" ]; then
    check_url "http://[::1]/healthz"
    check_url "https://[::1]/healthz" -k
fi
