#!/bin/bash

set -eu

# Replace password placeholders in config
if [ -n "$SIPCALLER1_PASSWORD" ]; then
    SIPCALLER1_PASSWORD_ESCAPED="$(printf '%s' "$SIPCALLER1_PASSWORD" | sed 's/[\/&|\\]/\\&/g')"
    sed -i "s/__SIPCALLER1_PASSWORD__/$SIPCALLER1_PASSWORD_ESCAPED/g" /opt/freeswitch/conf/directory/default.xml
fi

mkdir -p /var/lib/freeswitch/tls
cat /etc/certstore/fullchain.pem /etc/certstore/privkey.pem > /var/lib/freeswitch/tls/wss.pem
chmod 600 /var/lib/freeswitch/tls/wss.pem

rm -f /var/lib/freeswitch/db/lua_sqli_demo.db.db

sqlite3 /var/lib/freeswitch/db/lua_sqli_demo.db <<'SQL'
CREATE TABLE IF NOT EXISTS did_routes (
    did VARCHAR(255) PRIMARY KEY,
    target VARCHAR(32) NOT NULL,
    scope VARCHAR(16) NOT NULL
);
INSERT OR REPLACE INTO did_routes VALUES('2001', '2001', 'public');
INSERT OR REPLACE INTO did_routes VALUES('9000', '9000', 'internal');
SQL

exec /opt/freeswitch/bin/freeswitch -nonat -nc -nf -c \
    -conf /opt/freeswitch/conf \
    -log /var/log/freeswitch \
    -db /var/lib/freeswitch/db
