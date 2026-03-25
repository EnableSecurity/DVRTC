#!/bin/sh
set -eu

log_error() {
    if [ -s "$1" ]; then
        sed 's/^/mysqlclient: exporter failed: /' "$1" >&2
    fi
}

state=starting
while :
do
    tmpfile=$(mktemp)
    errfile=$(mktemp)
    chmod +r "$tmpfile"
    if python3 dump-uas.py >"$tmpfile" 2>"$errfile"; then
        mv "$tmpfile" /log/useragents.json
        if [ "$state" != "ready" ]; then
            echo "mysqlclient: user-agent export ready"
            state=ready
        fi
    else
        if [ "$state" != "waiting" ]; then
            echo "mysqlclient: waiting for useragents database initialization"
            log_error "$errfile"
            state=waiting
        fi
        rm -f "$tmpfile"
    fi
    rm -f "$errfile"
    sleep 1
done
