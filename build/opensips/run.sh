#!/bin/bash

set -eu

# Default to 0.0.0.0 if PUBLIC_IPV4 not set (for local testing)
PUBLIC_IPV4="${PUBLIC_IPV4:-0.0.0.0}"

# Build listen addresses
LISTEN="-l udp:$PUBLIC_IPV4:5060 -l tcp:$PUBLIC_IPV4:5060"

# Add TLS if certificates exist
if [ -f /etc/certstore/fullchain.pem ] && [ -f /etc/certstore/privkey.pem ]; then
    LISTEN="$LISTEN -l tls:$PUBLIC_IPV4:5061"
fi

# Add IPv6 if configured
if [ ! -z ${PUBLIC_IPV6+x} ] && [ -n "$PUBLIC_IPV6" ]; then
    LISTEN="$LISTEN -l udp:[$PUBLIC_IPV6]:5060 -l tcp:[$PUBLIC_IPV6]:5060"
    if [ -f /etc/certstore/fullchain.pem ]; then
        LISTEN="$LISTEN -l tls:[$PUBLIC_IPV6]:5061"
    fi
fi

# Add WireGuard if configured
if [ ! -z ${WG_IPV4+x} ] && [ -n "$WG_IPV4" ]; then
    LISTEN="$LISTEN -l udp:$WG_IPV4:5060 -l tcp:$WG_IPV4:5060"
fi

# Add localhost listener for FreeSWITCH responses (only if not already listening on all interfaces)
if [ "$PUBLIC_IPV4" != "0.0.0.0" ]; then
    LISTEN="$LISTEN -l udp:127.0.0.1:5060 -l tcp:127.0.0.1:5060"
fi

if [ -f /etc/certstore/fullchain.pem ] && [ -f /etc/certstore/privkey.pem ]; then
    chmod 640 /etc/certstore/privkey.pem || true
fi

exec opensips -F $LISTEN
