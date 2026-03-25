#!/bin/bash
set -eu

CONFIG_DIR="/etc/asterisk"
TEMPLATE_DIR="/var/lib/asterisk-config-template"
TEMPLATE_PJSIP_CONF="${TEMPLATE_DIR}/pjsip.conf"
LIVE_PJSIP_CONF="${CONFIG_DIR}/pjsip.conf"

# Validate required environment variables
if [ -z "$SIPCALLER1_PASSWORD" ]; then
    echo "ERROR: SIPCALLER1_PASSWORD is not set"
    echo "Run: ./scripts/generate_passwords.sh"
    exit 1
fi

PASSWORD_ESCAPED="$(printf '%s' "$SIPCALLER1_PASSWORD" | sed 's/[\/&|\\]/\\&/g')"
TMP_PJSIP_CONF="$(mktemp "${CONFIG_DIR}/pjsip.conf.XXXXXX")"
cp "$TEMPLATE_PJSIP_CONF" "$TMP_PJSIP_CONF"
sed -i "s|__SIPCALLER1_PASSWORD__|$PASSWORD_ESCAPED|g" "$TMP_PJSIP_CONF"
mv "$TMP_PJSIP_CONF" "$LIVE_PJSIP_CONF"
chmod 0644 "$LIVE_PJSIP_CONF"

# Create and ensure proper ownership of directories
mkdir -p /var/spool/asterisk /var/log/asterisk /var/run/asterisk
chown -R asterisk:asterisk /var/spool/asterisk /var/log/asterisk /var/run/asterisk

# Keep Asterisk from hitting low default soft nofile limits under callgen load.
exec runuser -u asterisk -- sh -c 'ulimit -n 65535; exec /usr/sbin/asterisk -f'
