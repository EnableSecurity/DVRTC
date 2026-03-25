#!/bin/bash

if ! [ -x "$(command -v docker)" ]; then
  echo 'Error: docker is not installed.' >&2
  exit 1
fi

source .env

if [ -z "${DOMAIN:-}" ]; then
  echo "Please set the DOMAIN env variable in .env"
  exit 1
fi

if [ -z "${EMAIL:-}" ]; then
  echo "Please set the EMAIL env variable in .env"
  exit 1
fi

domains=($DOMAIN)
rsa_key_size=4096
email=$EMAIL

staging=0 # Set to 1 if you're testing your setup to avoid hitting request limits
certstore="data/certs"
mkdir -p "$certstore"

host_uid=$(id -u)
host_gid=$(id -g)

echo "### Requesting Let's Encrypt certificate for $domains ..."
#Join $domains to -d args
domain_args=""
for domain in "${domains[@]}"; do
  domain_args="$domain_args -d $domain"
done

# Select appropriate email arg
case "$email" in
  "") email_arg="--register-unsafely-without-email" ;;
  *) email_arg="--email $email" ;;
esac

# Enable staging mode if needed
if [ $staging != "0" ]; then staging_arg="--staging"; fi

docker compose run -p80:80 --rm --entrypoint "\
  /bin/sh -ec '
    certbot certonly --standalone \
      $staging_arg \
      $email_arg \
      $domain_args \
      --rsa-key-size $rsa_key_size \
      --agree-tos \
      --force-renewal \
      --deploy-hook \"cp /etc/letsencrypt/live/$DOMAIN/* /etc/certstore && chown ${host_uid}:${host_gid} /etc/certstore/*\"
  '" certbot

# Generate DH parameters for nginx TLS if not present
dhparams="$certstore/ssl-dhparams.pem"
if [ ! -f "$dhparams" ]; then
    echo "### Generating DH parameters ..."
    docker compose run --rm --entrypoint "\
      /bin/sh -ec '
        openssl dhparam -out /etc/certstore/ssl-dhparams.pem 2048
        chown ${host_uid}:${host_gid} /etc/certstore/ssl-dhparams.pem
      '" certbot
else
    echo "### DH parameters already exist"
fi

echo
