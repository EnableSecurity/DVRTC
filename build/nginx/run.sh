#!/bin/bash

CERT_DIR="/etc/certstore"

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

while :; do sleep 6h & wait ${!}; nginx -s reload; done & nginx -g "daemon off;"
