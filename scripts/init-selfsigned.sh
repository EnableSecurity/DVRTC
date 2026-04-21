#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="$REPO_ROOT/.env"
CERTSTORE="$REPO_ROOT/data/certs"
TMP_COMPOSE="$(mktemp "${TMPDIR:-/tmp}/dvrtc-certbot.XXXXXX.yml")"

cleanup() {
    rm -f "$TMP_COMPOSE"
}
trap cleanup EXIT INT TERM

# Load public IPs from .env if it exists. Treat the file as shell syntax
# instead of trying to parse it with grep/xargs.
if [ -f "$ENV_FILE" ]; then
    set -a
    . "$ENV_FILE"
    set +a
fi

PUBLIC_IPV4="${PUBLIC_IPV4:-}"
PUBLIC_IPV6="${PUBLIC_IPV6:-}"

SAN_ENTRIES="DNS:localhost,IP:127.0.0.1"
if [ -n "$PUBLIC_IPV4" ]; then
    SAN_ENTRIES="$SAN_ENTRIES,IP:${PUBLIC_IPV4}"
fi
if [ -n "$PUBLIC_IPV6" ]; then
    SAN_ENTRIES="$SAN_ENTRIES,IP:${PUBLIC_IPV6}"
fi

mkdir -p "$CERTSTORE"

host_uid=$(id -u)
host_gid=$(id -g)

cat > "$TMP_COMPOSE" <<EOF
services:
  certbot:
    image: certbot/certbot:v5.4.0
    volumes:
      - type: bind
        source: $CERTSTORE
        target: /etc/certstore
EOF

set_runtime_cert_permissions() {
    # Some scenario services (notably FreeSWITCH and OpenSIPS in pbx2) run as
    # non-root users and read the bind-mounted cert files directly. Keep the
    # generated PEM files readable on these dedicated lab hosts so all runtime
    # services can start consistently.
    chmod 644 "$CERTSTORE/fullchain.pem" "$CERTSTORE/privkey.pem"
    if [ -f "$CERTSTORE/ssl-dhparams.pem" ]; then
        chmod 644 "$CERTSTORE/ssl-dhparams.pem"
    fi
}

compose_cmd=(docker compose -f "$TMP_COMPOSE" --project-directory "$REPO_ROOT")

echo "### Creating self-signed certificate for localhost${PUBLIC_IPV4:+, ${PUBLIC_IPV4}}${PUBLIC_IPV6:+, ${PUBLIC_IPV6}}"

# Create certificate with both localhost and IP address as Subject Alternative Names.
"${compose_cmd[@]}" run --rm --entrypoint "\
  /bin/sh -ec '
    openssl req -x509 -nodes -newkey rsa:4096 -days 365 \
      -keyout /etc/certstore/privkey.pem \
      -out /etc/certstore/fullchain.pem \
      -subj \"/CN=localhost\" \
      -addext \"subjectAltName=${SAN_ENTRIES}\"
    chown ${host_uid}:${host_gid} /etc/certstore/privkey.pem /etc/certstore/fullchain.pem
  '" certbot
set_runtime_cert_permissions

# Generate DH parameters for nginx TLS if not present.
dhparams="$CERTSTORE/ssl-dhparams.pem"
if [ ! -f "$dhparams" ]; then
    echo "### Generating DH parameters ..."
    "${compose_cmd[@]}" run --rm --entrypoint "\
      /bin/sh -ec '
        openssl dhparam -out /etc/certstore/ssl-dhparams.pem 2048
        chown ${host_uid}:${host_gid} /etc/certstore/ssl-dhparams.pem
      '" certbot
else
    echo "### DH parameters already exist"
fi

set_runtime_cert_permissions

echo
