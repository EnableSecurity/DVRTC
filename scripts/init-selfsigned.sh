#!/bin/bash

# Load public IPs from .env if it exists. Treat the file as shell syntax
# instead of trying to parse it with grep/xargs.
if [ -f .env ]; then
    set -a
    . ./.env
    set +a
fi

SAN_ENTRIES="DNS:localhost,IP:127.0.0.1"
if [ -n "$PUBLIC_IPV4" ]; then
    SAN_ENTRIES="$SAN_ENTRIES,IP:${PUBLIC_IPV4}"
fi
if [ -n "$PUBLIC_IPV6" ]; then
    SAN_ENTRIES="$SAN_ENTRIES,IP:${PUBLIC_IPV6}"
fi

certstore="data/certs"
mkdir -p "$certstore"

host_uid=$(id -u)
host_gid=$(id -g)

echo "### Creating self-signed certificate for localhost${PUBLIC_IPV4:+, ${PUBLIC_IPV4}}${PUBLIC_IPV6:+, ${PUBLIC_IPV6}}"
path="/etc/certstore"

# Create certificate with both localhost and IP address as Subject Alternative Names
docker compose run --rm --entrypoint "\
  /bin/sh -ec '
    openssl req -x509 -nodes -newkey rsa:4096 -days 365 \
      -keyout \"$path/privkey.pem\" \
      -out \"$path/fullchain.pem\" \
      -subj \"/CN=localhost\" \
      -addext \"subjectAltName=${SAN_ENTRIES}\"
    chown ${host_uid}:${host_gid} \"$path/privkey.pem\" \"$path/fullchain.pem\"
  '" certbot

# Generate DH parameters for nginx TLS if not present
dhparams="$certstore/ssl-dhparams.pem"
if [ ! -f "$dhparams" ]; then
    echo "### Generating DH parameters ..."
    docker compose run --rm --entrypoint "\
      /bin/sh -ec '
        openssl dhparam -out \"$path/ssl-dhparams.pem\" 2048
        chown ${host_uid}:${host_gid} \"$path/ssl-dhparams.pem\"
      '" certbot
else
    echo "### DH parameters already exist"
fi

echo
