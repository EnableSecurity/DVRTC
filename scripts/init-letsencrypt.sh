#!/bin/bash

set -euo pipefail

if ! [ -x "$(command -v docker)" ]; then
  echo 'Error: docker is not installed.' >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="$REPO_ROOT/.env"
CERTSTORE="$REPO_ROOT/data/certs"
TMP_COMPOSE="$(mktemp "${TMPDIR:-/tmp}/dvrtc-certbot.XXXXXX.yml")"

cleanup() {
  rm -f "$TMP_COMPOSE"
}
trap cleanup EXIT INT TERM

if [ ! -f "$ENV_FILE" ]; then
  echo "Please create $ENV_FILE first"
  exit 1
fi

set -a
. "$ENV_FILE"
set +a

DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-}"

if [ -z "$DOMAIN" ]; then
  echo "Please set the DOMAIN env variable in .env"
  exit 1
fi

if [ -z "$EMAIL" ]; then
  echo "Please set the EMAIL env variable in .env"
  exit 1
fi

domains=($DOMAIN)
rsa_key_size=4096
email=$EMAIL
staging=0 # Set to 1 if you're testing your setup to avoid hitting request limits

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

echo "### Requesting Let's Encrypt certificate for $domains ..."
# Join $domains to -d args.
domain_args=""
for domain in "${domains[@]}"; do
  domain_args="$domain_args -d $domain"
done

# Select appropriate email arg.
case "$email" in
  "") email_arg="--register-unsafely-without-email" ;;
  *) email_arg="--email $email" ;;
esac

# Enable staging mode if needed.
staging_arg=""
if [ "$staging" != "0" ]; then
  staging_arg="--staging"
fi

"${compose_cmd[@]}" run -p80:80 --rm --entrypoint "\
  /bin/sh -ec '
    certbot certonly --standalone \
      $staging_arg \
      $email_arg \
      $domain_args \
      --rsa-key-size $rsa_key_size \
      --agree-tos \
      --force-renewal \
      --deploy-hook \"cp /etc/letsencrypt/live/$DOMAIN/* /etc/certstore && chown ${host_uid}:${host_gid} /etc/certstore/* && chmod 644 /etc/certstore/fullchain.pem /etc/certstore/privkey.pem\"
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
