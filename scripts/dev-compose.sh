#!/bin/sh

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

DEFAULT_SOURCE_URL="https://github.com/EnableSecurity/DVRTC"
COMPOSE_FILE="$REPO_ROOT/docker-compose.yml"
DEV_COMPOSE_FILE="$REPO_ROOT/docker-compose.dev.yml"

usage() {
    cat <<'EOF'
Usage:
  ./scripts/dev-compose.sh [docker compose args...]

Examples:
  ./scripts/dev-compose.sh build
  ./scripts/dev-compose.sh up -d
  ./scripts/dev-compose.sh --profile testing build testing attacker

Defaults:
  DVRTC_VERSION defaults to the contents of VERSION
  VCS_REF defaults to the current git commit

Override DVRTC_VERSION explicitly when you intentionally want non-release metadata:
  DVRTC_VERSION=dev ./scripts/dev-compose.sh build nginx
EOF
}

if [ $# -eq 0 ]; then
    usage >&2
    exit 1
fi

VERSION="$(tr -d '\n' < "$REPO_ROOT/VERSION")"
VCS_REF_DEFAULT="unknown"
if git -C "$REPO_ROOT" rev-parse --short=12 HEAD >/dev/null 2>&1; then
    VCS_REF_DEFAULT="$(git -C "$REPO_ROOT" rev-parse --short=12 HEAD)"
fi

export DVRTC_VERSION="${DVRTC_VERSION:-$VERSION}"
export VCS_REF="${VCS_REF:-$VCS_REF_DEFAULT}"
export DVRTC_SOURCE="${DVRTC_SOURCE:-$DEFAULT_SOURCE_URL}"

exec docker compose -f "$COMPOSE_FILE" -f "$DEV_COMPOSE_FILE" "$@"
