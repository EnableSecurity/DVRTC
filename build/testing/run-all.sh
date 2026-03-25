#!/bin/sh
set -eu

normalize_host() {
    case "$1" in
        \[*\])
            printf '%s\n' "${1#\[}" | sed 's/\]$//'
            ;;
        *)
            printf '%s\n' "$1"
            ;;
    esac
}

format_uri_host() {
    host="$(normalize_host "$1")"
    case "$host" in
        *:*)
            printf '[%s]\n' "$host"
            ;;
        *)
            printf '%s\n' "$host"
            ;;
    esac
}

TARGET_INPUT="${1:-127.0.0.1}"
TARGET_IP="$(normalize_host "${TARGET_INPUT}")"
TARGET_SIP_HOST="$(format_uri_host "${TARGET_INPUT}")"
DIGEST_EXT="2000"
TARGET_MYSQL_PORT="${2:-${MYSQL_PORT:-23306}}"

SMOKE_EXT="${SMOKE_EXT:-1000}"
ENUM_EXT="${ENUM_EXT:-${DIGEST_EXT}}"
WEAK_USER="${WEAK_USER:-1000}"
WEAK_PASS="${WEAK_PASS:-1500}"

RUN_SMOKE_CHECK="${RUN_SMOKE_CHECK:-1}"
RUN_TURN_CHECK="${RUN_TURN_CHECK:-1}"
RUN_RTP_BLEED_CHECK="${RUN_RTP_BLEED_CHECK:-1}"
RUN_SIP_FLOOD_CHECK="${RUN_SIP_FLOOD_CHECK:-1}"
RUN_OFFLINE_CRACK_CHECK="${RUN_OFFLINE_CRACK_CHECK:-1}"

WEAK_CRED_TIMEOUT="${WEAK_CRED_TIMEOUT:-25}"
SQLI_TIMEOUT="${SQLI_TIMEOUT:-20}"
XSS_TIMEOUT="${XSS_TIMEOUT:-20}"
SIP_FLOOD_REQUESTS="${SIP_FLOOD_REQUESTS:-200}"
SIP_FLOOD_COLLECT_SECONDS="${SIP_FLOOD_COLLECT_SECONDS:-4}"
SIP_FLOOD_MIN_RESPONSES="${SIP_FLOOD_MIN_RESPONSES:-20}"
OFFLINE_CRACK_MAX_RUNTIME="${OFFLINE_CRACK_MAX_RUNTIME:-8}"
OFFLINE_CRACK_TIMEOUT="${OFFLINE_CRACK_TIMEOUT:-20}"
OFFLINE_CRACK_CANDIDATES="${OFFLINE_CRACK_CANDIDATES:-2000,1500,1234,password,admin,joshua,1000}"
RTP_BLEED_HOST="${RTP_BLEED_HOST:-}"
RTP_BLEED_START_PORT="${RTP_BLEED_START_PORT:-35000}"
RTP_BLEED_END_PORT="${RTP_BLEED_END_PORT:-40000}"
RTP_BLEED_DURATION="${RTP_BLEED_DURATION:-6}"
RTP_BLEED_PROBES="${RTP_BLEED_PROBES:-1}"
RTP_BLEED_CYCLE_LISTEN="${RTP_BLEED_CYCLE_LISTEN:-0.05}"
RTP_BLEED_LISTEN="${RTP_BLEED_LISTEN:-1.0}"
RTP_BLEED_PAYLOAD_TYPE="${RTP_BLEED_PAYLOAD_TYPE:-0}"
RTP_BLEED_ATTEMPTS="${RTP_BLEED_ATTEMPTS:-3}"

RUN_REGISTER_CHECK="${RUN_REGISTER_CHECK:-1}"
RUN_BAD_AUTH_CHECK="${RUN_BAD_AUTH_CHECK:-1}"
RUN_TRANSPORT_CHECK="${RUN_TRANSPORT_CHECK:-1}"
RUN_WSS_REGISTER_CHECK="${RUN_WSS_REGISTER_CHECK:-1}"
RUN_CALLGEN_CHECK="${RUN_CALLGEN_CHECK:-1}"
RUN_DIGESTLEAK_REG_CHECK="${RUN_DIGESTLEAK_REG_CHECK:-1}"
RUN_VOICEMAIL_CHECK="${RUN_VOICEMAIL_CHECK:-1}"
KAMCMD_ADDR="${KAMCMD_ADDR:-tcp:127.0.0.1:2046}"
VOICEMAIL_DURATION="${VOICEMAIL_DURATION:-10}"

if [ "${RUN_SMOKE_CHECK}" = "1" ]; then
    echo "[*] Running baseline smoke checks"
    python3 /opt/testing/scripts/dvrtc-checks.py \
        smoke \
        --host "${TARGET_IP}" \
        --extension "${SMOKE_EXT}" \
        --mysql-port "${TARGET_MYSQL_PORT}"
else
    echo "[*] Skipping smoke checks (RUN_SMOKE_CHECK=${RUN_SMOKE_CHECK})"
fi

if [ "${RUN_REGISTER_CHECK}" = "1" ]; then
    echo "[*] Running registration check"
    python3 /opt/testing/scripts/dvrtc-checks.py \
        register \
        --host "${TARGET_IP}" \
        --username "${WEAK_USER}" \
        --password "${WEAK_PASS}" \
        --timeout "${WEAK_CRED_TIMEOUT}"
else
    echo "[*] Skipping registration check (RUN_REGISTER_CHECK=${RUN_REGISTER_CHECK})"
fi

if [ "${RUN_BAD_AUTH_CHECK}" = "1" ]; then
    echo "[*] Running bad-auth check"
    python3 /opt/testing/scripts/dvrtc-checks.py \
        bad-auth \
        --host "${TARGET_IP}" \
        --username "${WEAK_USER}" \
        --timeout "${WEAK_CRED_TIMEOUT}"
else
    echo "[*] Skipping bad-auth check (RUN_BAD_AUTH_CHECK=${RUN_BAD_AUTH_CHECK})"
fi

if [ "${RUN_TRANSPORT_CHECK}" = "1" ]; then
    echo "[*] Running SIP transport check"
    python3 /opt/testing/scripts/dvrtc-checks.py \
        sip-transport \
        --host "${TARGET_IP}"
else
    echo "[*] Skipping SIP transport check (RUN_TRANSPORT_CHECK=${RUN_TRANSPORT_CHECK})"
fi

if [ "${RUN_WSS_REGISTER_CHECK}" = "1" ]; then
    echo "[*] Running WSS register check"
    python3 /opt/testing/scripts/dvrtc-checks.py \
        wss-register \
        --host "${TARGET_IP}"
else
    echo "[*] Skipping WSS register check (RUN_WSS_REGISTER_CHECK=${RUN_WSS_REGISTER_CHECK})"
fi

if [ "${RUN_CALLGEN_CHECK}" = "1" ]; then
    echo "[*] Running callgen-active check"
    python3 /opt/testing/scripts/dvrtc-checks.py \
        callgen-active \
        --host "${TARGET_IP}"
else
    echo "[*] Skipping callgen-active check (RUN_CALLGEN_CHECK=${RUN_CALLGEN_CHECK})"
fi

if [ "${RUN_DIGESTLEAK_REG_CHECK}" = "1" ]; then
    echo "[*] Running digestleak-registered check"
    python3 /opt/testing/scripts/dvrtc-checks.py \
        digestleak-registered \
        --host "${TARGET_IP}" \
        --kamcmd-addr "${KAMCMD_ADDR}"
else
    echo "[*] Skipping digestleak-registered check (RUN_DIGESTLEAK_REG_CHECK=${RUN_DIGESTLEAK_REG_CHECK})"
fi

if [ "${RUN_VOICEMAIL_CHECK}" = "1" ]; then
    echo "[*] Running voicemail check"
    python3 /opt/testing/scripts/dvrtc-checks.py \
        voicemail \
        --host "${TARGET_IP}" \
        --duration "${VOICEMAIL_DURATION}"
else
    echo "[*] Skipping voicemail check (RUN_VOICEMAIL_CHECK=${RUN_VOICEMAIL_CHECK})"
fi

echo "[*] Running enumeration check against ${TARGET_SIP_HOST}:${ENUM_EXT}"
python3 /opt/testing/scripts/dvrtc-checks.py \
    enum \
    --host "${TARGET_IP}" \
    --extension "${ENUM_EXT}"

echo "[*] Running weak credential check"
python3 /opt/testing/scripts/dvrtc-checks.py \
    weak-cred \
    --host "${TARGET_IP}" \
    --username "${WEAK_USER}" \
    --password "${WEAK_PASS}" \
    --timeout "${WEAK_CRED_TIMEOUT}"

echo "[*] Running SIP -> SQLi check"
python3 /opt/testing/scripts/dvrtc-checks.py \
    sqli \
    --host "${TARGET_IP}" \
    --extension "${SMOKE_EXT}" \
    --timeout "${SQLI_TIMEOUT}"

echo "[*] Running SIP -> XSS path check"
python3 /opt/testing/scripts/dvrtc-checks.py \
    xss \
    --host "${TARGET_IP}" \
    --extension "${SMOKE_EXT}" \
    --timeout "${XSS_TIMEOUT}"

echo "[*] Running digest leak check"

DIGEST_OK=0
DIGEST_OUTPUT=""
DIGEST_HASH=""
for ATTEMPT in 1 2 3; do
    echo "[*] Digest leak attempt ${ATTEMPT}/3"
    if DIGEST_OUTPUT="$(python3 /opt/testing/scripts/digestleak.py "${TARGET_IP}" "${DIGEST_EXT}" 2>&1)"; then
        echo "${DIGEST_OUTPUT}"
        DIGEST_OK=1
        DIGEST_HASH="$(printf '%s\n' "${DIGEST_OUTPUT}" | grep '^\$sip\$' | tail -n 1 || true)"
        break
    fi
    echo "${DIGEST_OUTPUT}"
    sleep 1
done

[ "${DIGEST_OK}" -eq 1 ] || {
    echo "[!] Digest leak check failed after 3 attempts"
    exit 1
}

if [ "${RUN_OFFLINE_CRACK_CHECK}" = "1" ]; then
    [ -n "${DIGEST_HASH}" ] || {
        echo "[!] Offline crack check failed: digest hash line was not captured"
        exit 1
    }
    echo "[*] Running offline SIP digest crack check (john)"
    python3 /opt/testing/scripts/dvrtc-checks.py \
        offline-crack \
        --hash-line "${DIGEST_HASH}" \
        --expected-password "${DIGEST_EXT}" \
        --candidates "${OFFLINE_CRACK_CANDIDATES}" \
        --max-run-time "${OFFLINE_CRACK_MAX_RUNTIME}" \
        --timeout "${OFFLINE_CRACK_TIMEOUT}"
else
    echo "[*] Skipping offline crack check (RUN_OFFLINE_CRACK_CHECK=${RUN_OFFLINE_CRACK_CHECK})"
fi

if [ "${RUN_TURN_CHECK}" = "1" ]; then
    TURN_HOST="${TURN_HOST:-${PUBLIC_IPV4:-${TARGET_IP}}}"
    TURN_PORT="${TURN_PORT:-3478}"
    TURN_USER="${TURN_USER:-user}"
    TURN_PASS="${TURN_PASS:-joshua}"
    TURN_PEER="${TURN_PEER:-127.0.0.1}"
    TURN_PEER_PORT="${TURN_PEER_PORT:-80}"
    TURN_PATH="${TURN_PATH:-/secret/}"
    TURN_EXPECT_STATUS="${TURN_EXPECT_STATUS:-200}"
    TURN_EXPECT_BODY="${TURN_EXPECT_BODY:-shutdown the Internet}"
    TURN_DENY_PEER="${TURN_DENY_PEER:-8.8.8.8}"
    TURN_DENY_PEER_PORT="${TURN_DENY_PEER_PORT:-53}"

    echo "[*] Running TURN unauthenticated allocate check"
    python3 /opt/testing/scripts/turn-probe.py \
        unauth-allocate \
        --host "${TURN_HOST}" \
        --port "${TURN_PORT}" \
        --expect deny

    echo "[*] Running TURN authenticated create-permission check"
    python3 /opt/testing/scripts/turn-probe.py \
        create-permission \
        --host "${TURN_HOST}" \
        --port "${TURN_PORT}" \
        --username "${TURN_USER}" \
        --password "${TURN_PASS}" \
        --peer "${TURN_PEER}" \
        --peer-port "${TURN_PEER_PORT}" \
        --expect allow

    echo "[*] Running TURN relay fetch check"
    python3 /opt/testing/scripts/turn-probe.py \
        tcp-http-get \
        --host "${TURN_HOST}" \
        --port "${TURN_PORT}" \
        --username "${TURN_USER}" \
        --password "${TURN_PASS}" \
        --peer "${TURN_PEER}" \
        --peer-port "${TURN_PEER_PORT}" \
        --path "${TURN_PATH}" \
        --expect-status "${TURN_EXPECT_STATUS}" \
        --expect-body "${TURN_EXPECT_BODY}"

    echo "[*] Running TURN disallowed-peer create-permission check"
    python3 /opt/testing/scripts/turn-probe.py \
        create-permission \
        --host "${TURN_HOST}" \
        --port "${TURN_PORT}" \
        --username "${TURN_USER}" \
        --password "${TURN_PASS}" \
        --peer "${TURN_DENY_PEER}" \
        --peer-port "${TURN_DENY_PEER_PORT}" \
        --expect deny
else
    echo "[*] Skipping TURN checks (RUN_TURN_CHECK=${RUN_TURN_CHECK})"
fi

if [ "${RUN_RTP_BLEED_CHECK}" = "1" ]; then
    echo "[*] Running RTP bleed check"
    if [ -n "${RTP_BLEED_HOST}" ]; then
        python3 /opt/testing/scripts/dvrtc-checks.py \
            rtp-bleed \
            --host "${TARGET_IP}" \
            --rtp-host "${RTP_BLEED_HOST}" \
            --start-port "${RTP_BLEED_START_PORT}" \
            --end-port "${RTP_BLEED_END_PORT}" \
            --duration "${RTP_BLEED_DURATION}" \
            --probes "${RTP_BLEED_PROBES}" \
            --cycle-listen "${RTP_BLEED_CYCLE_LISTEN}" \
            --listen "${RTP_BLEED_LISTEN}" \
            --payload-type "${RTP_BLEED_PAYLOAD_TYPE}" \
            --attempts "${RTP_BLEED_ATTEMPTS}"
    else
        python3 /opt/testing/scripts/dvrtc-checks.py \
            rtp-bleed \
            --host "${TARGET_IP}" \
            --start-port "${RTP_BLEED_START_PORT}" \
            --end-port "${RTP_BLEED_END_PORT}" \
            --duration "${RTP_BLEED_DURATION}" \
            --probes "${RTP_BLEED_PROBES}" \
            --cycle-listen "${RTP_BLEED_CYCLE_LISTEN}" \
            --listen "${RTP_BLEED_LISTEN}" \
            --payload-type "${RTP_BLEED_PAYLOAD_TYPE}" \
            --attempts "${RTP_BLEED_ATTEMPTS}"
    fi
else
    echo "[*] Skipping RTP bleed check (RUN_RTP_BLEED_CHECK=${RUN_RTP_BLEED_CHECK})"
fi

if [ "${RUN_SIP_FLOOD_CHECK}" = "1" ]; then
    echo "[*] Running SIP flood check"
    python3 /opt/testing/scripts/dvrtc-checks.py \
        sip-flood \
        --host "${TARGET_IP}" \
        --extension "${SMOKE_EXT}" \
        --requests "${SIP_FLOOD_REQUESTS}" \
        --collect-seconds "${SIP_FLOOD_COLLECT_SECONDS}" \
        --min-responses "${SIP_FLOOD_MIN_RESPONSES}"
else
    echo "[*] Skipping SIP flood check (RUN_SIP_FLOOD_CHECK=${RUN_SIP_FLOOD_CHECK})"
fi

echo "[+] All testing checks passed"
