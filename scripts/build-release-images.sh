#!/bin/sh

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PUSH=0
DEFAULT_SOURCE_URL="https://github.com/EnableSecurity/DVRTC"

usage() {
    cat <<'EOF'
Usage:
  ./scripts/build-release-images.sh [options]

Options:
  --push                 Push images after building
  -h, --help             Show this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --push)
            PUSH=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

VERSION="$(tr -d '\n' < "$REPO_ROOT/VERSION")"
VCS_REF="$(git -C "$REPO_ROOT" rev-parse --short=12 HEAD)"
COMPOSE_FILE="$REPO_ROOT/docker-compose.yml"
DEV_COMPOSE_FILE="$REPO_ROOT/docker-compose.dev.yml"
SERVICES="asterisk rtpengine kamailio baresip-callgen baresip-digestleak nginx voicemailcleaner mysqlclient dbcleaner db"
TESTING_SERVICE="testing"

export DVRTC_VERSION="$VERSION"
export VCS_REF="$VCS_REF"
export DVRTC_SOURCE="${DVRTC_SOURCE:-$DEFAULT_SOURCE_URL}"

echo "Building release images for ${VERSION}"
docker compose -f "$COMPOSE_FILE" -f "$DEV_COMPOSE_FILE" build $SERVICES
docker compose -f "$COMPOSE_FILE" -f "$DEV_COMPOSE_FILE" --profile testing build "$TESTING_SERVICE"

if [ "$PUSH" -eq 1 ]; then
    echo "Pushing release images for ${VERSION}"
    docker compose -f "$COMPOSE_FILE" -f "$DEV_COMPOSE_FILE" push $SERVICES
    docker compose -f "$COMPOSE_FILE" -f "$DEV_COMPOSE_FILE" --profile testing push "$TESTING_SERVICE"
fi
