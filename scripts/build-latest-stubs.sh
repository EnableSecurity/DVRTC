#!/bin/sh

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

IMAGE_PREFIX="ghcr.io/enablesecurity/dvrtc"
PUSH=0
SCENARIO="pbx1"
DEFAULT_SOURCE_URL="https://github.com/EnableSecurity/DVRTC"

usage() {
    cat <<'EOF'
Usage:
  ./scripts/build-latest-stubs.sh [options]

Options:
  --scenario pbx1|pbx2   Build latest stubs for the selected scenario image set
  --image-prefix PREFIX  Tag stub images under PREFIX/<service>
                         Default: ghcr.io/enablesecurity/dvrtc
  --push                 Push images after building
  -h, --help             Show this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --image-prefix)
            if [ $# -lt 2 ]; then
                echo "ERROR: --image-prefix requires a value" >&2
                exit 1
            fi
            IMAGE_PREFIX="$2"
            shift 2
            ;;
        --push)
            PUSH=1
            shift
            ;;
        --scenario)
            SCENARIO="${2:?missing scenario}"
            shift 2
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
DVRTC_SOURCE="${DVRTC_SOURCE:-$DEFAULT_SOURCE_URL}"
TMP_COMPOSE="$(mktemp "${TMPDIR:-/tmp}/dvrtc-latest-stubs.XXXXXX.yml")"

case "$SCENARIO" in
    pbx1)
        SERVICES="asterisk rtpengine kamailio baresip-callgen baresip-digestleak nginx voicemailcleaner mysqlclient dbcleaner db testing"
        ;;
    pbx2)
        SERVICES="pbx2-freeswitch pbx2-rtpproxy pbx2-opensips"
        ;;
    *)
        echo "ERROR: Unknown scenario: $SCENARIO" >&2
        exit 1
        ;;
esac

cleanup() {
    rm -f "$TMP_COMPOSE"
}
trap cleanup EXIT INT TERM

cat > "$TMP_COMPOSE" <<EOF
services:
EOF

for SERVICE in $SERVICES; do
    TARGET_IMAGE="${IMAGE_PREFIX}/${SERVICE}:${VERSION}"
    cat >> "$TMP_COMPOSE" <<EOF
  ${SERVICE}:
    image: ${IMAGE_PREFIX}/${SERVICE}:latest
    platform: linux/amd64
    build:
      context: ${REPO_ROOT}/build/latest-stub
      args:
        DVRTC_VERSION: ${VERSION}
        DVRTC_SERVICE: ${SERVICE}
        VCS_REF: ${VCS_REF}
        DVRTC_SOURCE: ${DVRTC_SOURCE}
        TARGET_IMAGE: ${TARGET_IMAGE}
EOF
done

echo "Building latest stub images pointing to ${VERSION}"
docker compose -f "$TMP_COMPOSE" build $SERVICES

if [ "$PUSH" -eq 1 ]; then
    echo "Pushing latest stub images"
    docker compose -f "$TMP_COMPOSE" push $SERVICES
fi
