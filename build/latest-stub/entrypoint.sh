#!/bin/sh

set -eu

echo "ERROR: ${DVRTC_SERVICE}:latest is a stub image." >&2
echo "Run ${TARGET_IMAGE} explicitly." >&2
exit 64
