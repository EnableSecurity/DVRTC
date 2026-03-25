#!/bin/sh
# Asterisk health check
# Avoid synthetic SIP calls in steady state. Asterisk is considered healthy
# once the core reports fully booted.

set -eu

OUTPUT="$(timeout 10 asterisk -rx "core waitfullybooted" 2>&1 || true)"

printf '%s\n' "$OUTPUT" | grep -q "Asterisk has fully booted"
