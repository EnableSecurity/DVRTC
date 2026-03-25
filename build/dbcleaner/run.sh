#!/bin/sh
set -eu

MYSQL_HOST="${MYSQL_HOST:-127.0.0.1}"
MYSQL_PORT="${MYSQL_PORT:-23306}"
# Keep the intentionally weak lab credential as the default, but make it
# overrideable so the password only lives in one place when the lab is adjusted.
MYSQL_USER="${MYSQL_USER:-kamailio}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-kamailiorw}"
MYSQL_DATABASE="${MYSQL_DATABASE:-useragents}"

state=starting
while :
do
    if echo "DELETE from useragents;" | mysql -u"${MYSQL_USER}" -p"${MYSQL_PASSWORD}" -h"${MYSQL_HOST}" -P"${MYSQL_PORT}" "${MYSQL_DATABASE}" >/dev/null 2>&1; then
        if [ "$state" != "ready" ]; then
            echo "dbcleaner: useragents cleanup ready"
            state=ready
        fi
        sleep 1h
    else
        if [ "$state" != "waiting" ]; then
            echo "dbcleaner: waiting for useragents database initialization"
            state=waiting
        fi
        sleep 5
    fi
done
