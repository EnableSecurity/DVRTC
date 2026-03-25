#!/bin/bash

set -eu

print_setup_help() {
    echo "DVRTC setup incomplete."
    echo "Run these commands before 'docker compose up':"
    echo "  ./scripts/setup_networking.sh"
    echo "  ./scripts/generate_passwords.sh"
    echo "  ./scripts/init-selfsigned.sh"
    echo "See README.md Initial Setup."
}

if [ -z "${PUBLIC_IPV4:-}" ]; then
    echo "ERROR: PUBLIC_IPV4 is not set"
    print_setup_help
    exit 1
fi

# Bind and advertise on the configured public address.
# Keep rtpengine's upstream media behavior permissive here: DVRTC relies on
# it for RTP bleed and injection exercises, so we only control the advertised
# interfaces rather than tightening source learning/relay behavior in this shim.
INTERFACES="--interface=${PUBLIC_IPV4}"

if [ -n "${PUBLIC_IPV6:-}" ]; then
    INTERFACES+=" --interface=${PUBLIC_IPV6}"
fi

exec rtpengine -f \
    $INTERFACES \
    --listen-ng="127.0.0.1:2223" \
    --pidfile=/opt/run/rtpengine/ngcp-rtpengine-daemon.pid \
    --port-min=35000 \
    --port-max=40000 \
    --max-sessions=1000 \
    --log-stderr \
    --log-level=3
