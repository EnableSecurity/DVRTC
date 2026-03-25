#!/bin/sh
# Kamailio health check
# Tests all SIP interfaces: UDP 5060, TCP 5060, TLS 5061, WS 8000, WSS 8443.
# These probes use Kamailio's own keepalive path and a WebSocket upgrade check.

set -eu

TIMEOUT=5000
CURL_TIMEOUT=5

sip_check() {
    NAME="$1"; RURI="$2"; shift 2
    if sipexer -nagios -timeout "$TIMEOUT" -ru "$RURI" "$@" >/dev/null 2>&1; then
        return 0
    fi
    echo "FAIL: $NAME" >&2
    exit 1
}

ws_check() {
    URL="$1"
    CODE="$(curl -g -s -o /dev/null -w "%{http_code}" --max-time "$CURL_TIMEOUT" \
        -H "Upgrade: websocket" \
        -H "Connection: Upgrade" \
        -H "Sec-WebSocket-Version: 13" \
        -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
        -H "Sec-WebSocket-Protocol: sip" \
        -H "User-Agent: dvrtc-healthcheck" \
        "$URL" 2>/dev/null || true)"
    [ "$CODE" = "101" ] || exit 1
}

sip_check "UDP 5060" "sip:127.0.0.1" udp:127.0.0.1:5060
sip_check "TCP 5060" "sip:127.0.0.1" tcp:127.0.0.1:5060
sip_check "TLS 5061" "sip:127.0.0.1" -ti tls:127.0.0.1:5061
ws_check "http://127.0.0.1:8000/"
sip_check "WSS 8443" "sip:127.0.0.1" -ti wss://127.0.0.1:8443

if [ -n "${PUBLIC_IPV6:-}" ]; then
    sip_check "UDP 5060 (IPv6)" "sip:[$PUBLIC_IPV6]" udp:[$PUBLIC_IPV6]:5060
    sip_check "TCP 5060 (IPv6)" "sip:[$PUBLIC_IPV6]" tcp:[$PUBLIC_IPV6]:5060
    sip_check "TLS 5061 (IPv6)" "sip:[$PUBLIC_IPV6]" -ti tls:[$PUBLIC_IPV6]:5061
    ws_check "http://[$PUBLIC_IPV6]:8000/"
    sip_check "WSS 8443 (IPv6)" "sip:[$PUBLIC_IPV6]" -ti wss://[$PUBLIC_IPV6]:8443
fi
