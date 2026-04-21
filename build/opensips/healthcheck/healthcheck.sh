#!/bin/sh
set -eu

printf 'OPTIONS sip:health@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5070;branch=z9hG4bK-dvrtc-hc\r\nFrom: <sip:health@127.0.0.1>;tag=dvrtc-hc\r\nTo: <sip:health@127.0.0.1>\r\nCall-ID: dvrtc-opensips-hc\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 5\r\nContent-Length: 0\r\n\r\n' \
  | timeout 10 nc -u -w2 127.0.0.1 5060 \
  | grep -q "200 Keepalive"
