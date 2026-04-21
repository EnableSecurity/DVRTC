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

# Replace password placeholder in a fresh copy of the template while escaping
# sed replacement metacharacters that may appear in generated secrets.
PASSWORD_ESCAPED="$(printf '%s' "$SIPCALLER1_PASSWORD" | sed 's/[\/&|\\]/\\&/g')"
cp "$TEMPLATE_ACCOUNTS" "$LIVE_ACCOUNTS"
sed -i "s|__SIPCALLER1_PASSWORD__|$PASSWORD_ESCAPED|g" "$LIVE_ACCOUNTS"

# Target media duration in seconds once the call is up.
CALL_DURATION=${CALL_DURATION:-60}
# Pause between calls (short to maximize overlap)
CALL_PAUSE=${CALL_PAUSE:-2}
# Give baresip extra headroom to shut down cleanly after its own timer fires.
EXIT_GRACE=${EXIT_GRACE:-10}
# Full cycle for one callgen instance: desired media time plus pause before the next call.
CALL_CYCLE=$((CALL_DURATION + CALL_PAUSE))

# docker-compose waits for Kamailio to be healthy before this container starts.
# Prefer a fixed startup delay when provided so multiple callgens can be
# intentionally staggered with predictable overlap. Fall back to randomized
# staggering for ad-hoc scaled deployments.
if [ -n "${CALL_START_DELAY:-}" ]; then
    log_info "Kamailio is healthy, delaying callgen startup by ${CALL_START_DELAY}s"
    sleep "$CALL_START_DELAY"
else
    CALL_START_SPREAD=${CALL_START_SPREAD:-$CALL_CYCLE}
    if [ "$CALL_START_SPREAD" -gt 0 ]; then
        RANDOM_OFFSET=$(shuf -i 0-$((CALL_START_SPREAD - 1)) -n 1)
        log_info "Kamailio is healthy, staggering callgen startup by ${RANDOM_OFFSET}s (spread=${CALL_START_SPREAD}s)"
        sleep "$RANDOM_OFFSET"
    fi
fi

log_info "Starting call generation loop (duration: ${CALL_DURATION}s, pause: ${CALL_PAUSE}s)..."

# Destination - can be overridden by CALL_DEST environment variable
CALL_DEST=${CALL_DEST:-1300}

# Collect available sound files
SOUNDS_DIR="/home/baresip/sounds"
CURRENT_LINK="${SOUNDS_DIR}/current.wav"

BARESIP_NET_IFACE="$(select_net_interface)"
BARESIP_NET_ARGS=""
if [ -n "$BARESIP_NET_IFACE" ]; then
    BARESIP_NET_ARGS="-n $BARESIP_NET_IFACE"
    log_info "Using baresip network interface: ${BARESIP_NET_IFACE}"
fi

# Main loop - make sequential calls using -e option
while true; do
    # Pick a random WAV file for this call
    WAV_FILES=$(find "$SOUNDS_DIR" -maxdepth 1 -name '*.wav' ! -name 'current.wav' 2>/dev/null)
    if [ -n "$WAV_FILES" ]; then
        CHOSEN=$(echo "$WAV_FILES" | shuf -n 1)
        ln -sf "$CHOSEN" "$CURRENT_LINK"
        log_info "Making call to ${CALL_DEST} with audio: $(basename "$CHOSEN")"
    else
        log_warn "No audio files found; calling ${CALL_DEST} with silence"
    fi

    # Run baresip with -e to dial, -t to auto-quit cleanly after duration
    # baresip's -t flag hangs up the call (sends BYE) before exiting.
    # The outer timeout is a last-resort safety net with extra headroom so
    # baresip's -t always fires first and never races with a SIGKILL.
    LOG_FILE=$(mktemp)
    if timeout $((CALL_DURATION + EXIT_GRACE)) sh -c '
        exec baresip ${1:+-n "$1"} -f "$2" -e "$3" -t "$4"
    ' sh "$BARESIP_NET_IFACE" "$CONFIG_DIR" "d sip:${CALL_DEST}@127.0.0.1" "$CALL_DURATION" \
        >"$LOG_FILE" 2>&1; then
        if [ "$CALLGEN_LOG_LEVEL" = "info" ]; then
            cat "$LOG_FILE"
        else
            grep -Ei 'warning|error|failed|fatal|panic' "$LOG_FILE" >&2 || true
        fi
    else
        STATUS=$?
        log_warn "baresip exited with status ${STATUS} while calling ${CALL_DEST}"
        sed -n '1,200p' "$LOG_FILE" >&2
    fi
    rm -f "$LOG_FILE"

    log_info "Call completed, pausing ${CALL_PAUSE}s..."
    sleep $CALL_PAUSE
done
