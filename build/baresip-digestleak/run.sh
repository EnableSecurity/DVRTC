#!/bin/sh

LOG_LEVEL=${DIGESTLEAK_LOG_LEVEL:-warn}
SIP_TRACE=${DIGESTLEAK_SIP_TRACE:-0}

log_info() {
    [ "$LOG_LEVEL" = "info" ] || return 0
    echo "$@"
}

log_warn() {
    echo "$@" >&2
}

# docker-compose waits for Kamailio to be healthy before this container starts.

log_info "Starting baresip for digest leak demo (extension 2000)..."
log_info "Will auto-answer incoming calls using answermode=auto."

# Hangup loop - sends hangup command every 2 seconds via ctrl_tcp
# Uses netstring format: length:json,
hangup_loop() {
    sleep 3  # Wait for baresip to start
    while true; do
        # Send hangup via ctrl_tcp (netstring format)
        response="$(printf '43:{"command":"hangup","params":"","token":""},' | nc -w1 127.0.0.1 4444 2>/dev/null || true)"
        if [ -n "$response" ] && ! printf '%s' "$response" | grep -q '"ok":true'; then
            log_warn "ctrl_tcp hangup returned unexpected response: $response"
        fi
        sleep 2
    done
}

# Start hangup loop in background
hangup_loop &

# Run baresip - ctrl_tcp keeps it running
if [ "$LOG_LEVEL" = "info" ]; then
    if [ "$SIP_TRACE" = "1" ]; then
        exec baresip -f /home/baresip/.baresip -v -s 2>&1
    fi
    exec baresip -f /home/baresip/.baresip -v 2>&1
fi

if [ "$SIP_TRACE" = "1" ]; then
    exec baresip -f /home/baresip/.baresip -s 2>&1
fi

exec baresip -f /home/baresip/.baresip 2>&1
