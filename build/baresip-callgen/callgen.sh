#!/bin/sh

# Validate required environment variables
if [ -z "$SIPCALLER1_PASSWORD" ]; then
    echo "ERROR: SIPCALLER1_PASSWORD is not set" >&2
    echo "Run: ./scripts/generate_passwords.sh" >&2
    exit 1
fi

CALLGEN_LOG_LEVEL=${CALLGEN_LOG_LEVEL:-warn}
CONFIG_DIR="/home/baresip/.baresip"
TEMPLATE_ACCOUNTS="${CONFIG_DIR}/accounts.template"
LIVE_ACCOUNTS="${CONFIG_DIR}/accounts"
LIVE_CONFIG="${CONFIG_DIR}/config"
SOUNDS_DIR="/home/baresip/sounds"
CURRENT_LINK="${SOUNDS_DIR}/current.wav"
CTRL_TCP_HOST="127.0.0.1"
CTRL_TCP_PORT=${CTRL_TCP_PORT:-4444}
CTRL_TCP_READY_TIMEOUT=${CTRL_TCP_READY_TIMEOUT:-15}
CTRL_TCP_SETTLE_TIMEOUT=${CTRL_TCP_SETTLE_TIMEOUT:-5}
BARESIP_LOG_FILE="${CONFIG_DIR}/baresip.log"
BARESIP_PID=""

select_net_interface() {
    if [ -n "${BARESIP_NET_INTERFACE:-}" ]; then
        printf '%s\n' "$BARESIP_NET_INTERFACE"
        return 0
    fi

    if [ -r /proc/net/route ]; then
        awk '$2 == "00000000" { print $1; exit }' /proc/net/route
        return 0
    fi

    return 0
}

log_info() {
    [ "$CALLGEN_LOG_LEVEL" = "info" ] || return 0
    printf '%s: %s\n' "$(date)" "$*"
}

log_warn() {
    printf '%s: %s\n' "$(date)" "$*" >&2
}

print_baresip_log_summary() {
    [ -r "$BARESIP_LOG_FILE" ] || return 0

    if [ "$CALLGEN_LOG_LEVEL" = "info" ]; then
        sed -n '1,200p' "$BARESIP_LOG_FILE"
        return 0
    fi

    grep -Ei 'segmentation fault|warning|error|failed|fatal|panic' "$BARESIP_LOG_FILE" >&2 || true
}

ctrl_tcp_request() {
    CMD_NAME=$1
    CMD_PARAMS=${2:-}
    CMD_TOKEN=${3:-callgen}
    PAYLOAD=$(printf '{"command":"%s","params":"%s","token":"%s"}' "$CMD_NAME" "$CMD_PARAMS" "$CMD_TOKEN")
    PAYLOAD_LEN=$(printf '%s' "$PAYLOAD" | wc -c | tr -d ' ')
    printf '%s:%s,' "$PAYLOAD_LEN" "$PAYLOAD" | nc -w1 "$CTRL_TCP_HOST" "$CTRL_TCP_PORT" 2>/dev/null || true
}

wait_for_ctrl_tcp() {
    ATTEMPT=0
    while [ "$ATTEMPT" -lt "$CTRL_TCP_READY_TIMEOUT" ]; do
        RESPONSE=$(ctrl_tcp_request help "" ready)
        if printf '%s' "$RESPONSE" | grep -q '"ok":true'; then
            return 0
        fi
        ATTEMPT=$((ATTEMPT + 1))
        sleep 1
    done
    return 1
}

wait_for_no_active_calls() {
    ATTEMPT=0
    while [ "$ATTEMPT" -lt "$CTRL_TCP_SETTLE_TIMEOUT" ]; do
        if ! kill -0 "$BARESIP_PID" 2>/dev/null; then
            return 1
        fi
        RESPONSE=$(ctrl_tcp_request listcalls "" listcalls)
        if printf '%s' "$RESPONSE" | grep -q 'Active calls (0)'; then
            return 0
        fi
        ATTEMPT=$((ATTEMPT + 1))
        sleep 1
    done
    return 1
}

sleep_with_process_watch() {
    SECONDS_LEFT=$1
    while [ "$SECONDS_LEFT" -gt 0 ]; do
        if ! kill -0 "$BARESIP_PID" 2>/dev/null; then
            return 1
        fi
        sleep 1
        SECONDS_LEFT=$((SECONDS_LEFT - 1))
    done
    return 0
}

pick_audio() {
    WAV_FILES=$(find "$SOUNDS_DIR" -maxdepth 1 -name '*.wav' ! -name 'current.wav' 2>/dev/null)
    if [ -n "$WAV_FILES" ]; then
        CHOSEN=$(printf '%s\n' "$WAV_FILES" | shuf -n 1)
        ln -sf "$CHOSEN" "$CURRENT_LINK"
        log_info "Using audio: $(basename "$CHOSEN")"
        return 0
    fi

    log_warn "No audio files found; calling ${CALL_DEST} with silence"
    return 0
}

start_baresip() {
    : > "$BARESIP_LOG_FILE"

    if [ -n "$BARESIP_NET_IFACE" ]; then
        log_info "Starting persistent baresip with interface ${BARESIP_NET_IFACE}"
        baresip -n "$BARESIP_NET_IFACE" -f "$CONFIG_DIR" >"$BARESIP_LOG_FILE" 2>&1 &
    else
        log_info "Starting persistent baresip"
        baresip -f "$CONFIG_DIR" >"$BARESIP_LOG_FILE" 2>&1 &
    fi
    BARESIP_PID=$!
}

stop_baresip() {
    if [ -z "$BARESIP_PID" ]; then
        return 0
    fi

    if kill -0 "$BARESIP_PID" 2>/dev/null; then
        ctrl_tcp_request hangup "" shutdown >/dev/null 2>&1 || true
        sleep 1
        kill "$BARESIP_PID" 2>/dev/null || true
        wait "$BARESIP_PID" 2>/dev/null || true
    fi
    BARESIP_PID=""
}

cleanup() {
    stop_baresip
    print_baresip_log_summary
}

trap 'cleanup; exit 0' INT TERM
trap 'cleanup' EXIT

# Replace password placeholder in a fresh copy of the template while escaping
# sed replacement metacharacters that may appear in generated secrets.
PASSWORD_ESCAPED="$(printf '%s' "$SIPCALLER1_PASSWORD" | sed 's/[\/&|\\]/\\&/g')"
cp "$TEMPLATE_ACCOUNTS" "$LIVE_ACCOUNTS"
sed -i "s|__SIPCALLER1_PASSWORD__|$PASSWORD_ESCAPED|g" "$LIVE_ACCOUNTS"
sed -i "s|__CTRL_TCP_PORT__|$CTRL_TCP_PORT|g" "$LIVE_CONFIG"

# Target media duration in seconds once the call is up.
CALL_DURATION=${CALL_DURATION:-60}
# Pause between calls (short to maximize overlap)
CALL_PAUSE=${CALL_PAUSE:-2}
# Full cycle for one callgen instance: desired media time plus pause before the next call.
CALL_CYCLE=$((CALL_DURATION + CALL_PAUSE))

# docker-compose waits for OpenSIPS / FreeSWITCH to be healthy before this container starts.
# Prefer a fixed startup delay when provided so multiple callgens can be
# intentionally staggered with predictable overlap. Fall back to randomized
# staggering for ad-hoc scaled deployments.
if [ -n "${CALL_START_DELAY:-}" ]; then
    log_info "Services are healthy, delaying callgen startup by ${CALL_START_DELAY}s"
    sleep "$CALL_START_DELAY"
else
    CALL_START_SPREAD=${CALL_START_SPREAD:-$CALL_CYCLE}
    if [ "$CALL_START_SPREAD" -gt 0 ]; then
        RANDOM_OFFSET=$(shuf -i 0-$((CALL_START_SPREAD - 1)) -n 1)
        log_info "Services are healthy, staggering callgen startup by ${RANDOM_OFFSET}s (spread=${CALL_START_SPREAD}s)"
        sleep "$RANDOM_OFFSET"
    fi
fi

log_info "Starting call generation loop (duration: ${CALL_DURATION}s, pause: ${CALL_PAUSE}s)..."

# Destination - can be overridden by CALL_DEST environment variable
CALL_DEST=${CALL_DEST:-1300}
BARESIP_NET_IFACE="$(select_net_interface)"
if [ -n "$BARESIP_NET_IFACE" ]; then
    log_info "Using baresip network interface: ${BARESIP_NET_IFACE}"
fi

while true; do
    start_baresip

    if ! wait_for_ctrl_tcp; then
        log_warn "ctrl_tcp did not become ready; restarting baresip"
        stop_baresip
        sleep 1
        continue
    fi

    while kill -0 "$BARESIP_PID" 2>/dev/null; do
        pick_audio

        DIAL_RESPONSE=$(ctrl_tcp_request dial "sip:${CALL_DEST}@127.0.0.1" dial)
        if ! printf '%s' "$DIAL_RESPONSE" | grep -q '"ok":true'; then
            log_warn "dial command failed: ${DIAL_RESPONSE}"
            sleep 1
            continue
        fi

        log_info "Call to ${CALL_DEST} started"

        if ! sleep_with_process_watch "$CALL_DURATION"; then
            break
        fi

        HANGUP_RESPONSE=$(ctrl_tcp_request hangup "" hangup)
        if ! printf '%s' "$HANGUP_RESPONSE" | grep -q '"ok":true'; then
            log_warn "hangup command failed: ${HANGUP_RESPONSE}"
        fi

        if ! wait_for_no_active_calls; then
            log_warn "baresip did not report a clean hangup before the next cycle"
        fi

        log_info "Call completed, pausing ${CALL_PAUSE}s..."
        sleep "$CALL_PAUSE"
    done

    wait "$BARESIP_PID" 2>/dev/null || STATUS=$?
    STATUS=${STATUS:-0}
    BARESIP_PID=""
    if [ "$STATUS" -ne 0 ]; then
        log_warn "persistent baresip exited with status ${STATUS}; restarting"
    else
        log_warn "persistent baresip exited unexpectedly; restarting"
    fi
    print_baresip_log_summary
    STATUS=0
    sleep 1
done
