#!/bin/bash

set -eu

if [ -z "$PUBLIC_IPV4" ]; then
    echo "ERROR: PUBLIC_IPV4 environment variable is not set"
    echo "Please set it in your .env file (e.g., PUBLIC_IPV4=127.0.0.1 for local testing)"
    exit 1
fi

# RTPProxy 3.x expects exactly one configured IPv4 listen address for this
# simple non-bridged deployment. pbx2 currently anchors media on IPv4 only.

# Recording options:
#   -r /recordings    = recording directory
#   -S /recordings/spool = spool for active recordings
#   -P                = pcap format (Wireshark compatible)
#   -a                = record ALL sessions unconditionally
exec rtpproxy -f \
    -p /var/run/rtpproxy/rtpproxy.pid \
    -s udp:127.0.0.1:7722 \
    -l "$PUBLIC_IPV4" \
    -m 35000 \
    -M 40000 \
    -d WARN \
    -F \
    -a \
    -r /recordings \
    -S /recordings/spool \
    -P
