#!/bin/bash

CERT_DIR="/etc/certstore"
SCENARIO="${DVRTC_NGINX_SCENARIO:-pbx1}"
SITE_DIR="/usr/share/dvrtc/site/${SCENARIO}"
CONFIG_TEMPLATE="/etc/nginx/sites-available/default.${SCENARIO}"

if [ ! -f "$CERT_DIR/fullchain.pem" ] || [ ! -f "$CERT_DIR/privkey.pem" ] || [ ! -f "$CERT_DIR/ssl-dhparams.pem" ]; then
    echo "ERROR: TLS material is missing from $CERT_DIR"
    echo "DVRTC setup incomplete."
    echo "Run these commands before 'docker compose up':"
    echo "  ./scripts/setup_networking.sh"
    echo "  ./scripts/generate_passwords.sh"
    echo "  ./scripts/init-selfsigned.sh"
    echo "See README.md Initial Setup."
    exit 1
fi

if [ ! -d "$SITE_DIR" ]; then
    echo "ERROR: unknown nginx scenario '$SCENARIO'"
    exit 1
fi

if [ ! -f "$CONFIG_TEMPLATE" ]; then
    echo "ERROR: nginx config template missing for scenario '$SCENARIO'"
    exit 1
fi

mkdir -p /var/www/html
cp -a "$SITE_DIR/." /var/www/html/
cp "$CONFIG_TEMPLATE" /etc/nginx/sites-available/default

while :; do sleep 6h & wait ${!}; nginx -s reload; done & nginx -g "daemon off;"
