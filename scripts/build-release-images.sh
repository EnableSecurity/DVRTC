#!/bin/sh

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="$REPO_ROOT/.env"

PUSH=0
SCENARIO="pbx1"
DEFAULT_SOURCE_URL="https://github.com/EnableSecurity/DVRTC"

usage() {
    cat <<'EOF'
Usage:
  ./scripts/build-release-images.sh [options]

Options:
  --scenario pbx1|pbx2   Build the selected scenario image set
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
BASE_COMPOSE_FILE="$REPO_ROOT/compose/base.yml"
BASE_DEV_COMPOSE_FILE="$REPO_ROOT/compose/dev.yml"
TESTING_SERVICE="testing"

case "$SCENARIO" in
    pbx1)
        SCENARIO_COMPOSE_FILE="$REPO_ROOT/compose/pbx1.yml"
        SCENARIO_DEV_COMPOSE_FILE="$REPO_ROOT/compose/dev.pbx1.yml"
        SERVICES="asterisk rtpengine kamailio baresip-callgen baresip-digestleak nginx voicemailcleaner mysqlclient dbcleaner db"
        ;;
    pbx2)
        SCENARIO_COMPOSE_FILE="$REPO_ROOT/compose/pbx2.yml"
        SCENARIO_DEV_COMPOSE_FILE="$REPO_ROOT/compose/dev.pbx2.yml"
        SERVICES="freeswitch rtpproxy opensips baresip-callgen-pbx2 baresip-digestleak-pbx2 nginx-pbx2"
        ;;
    *)
        echo "ERROR: Unknown scenario: $SCENARIO" >&2
        exit 1
        ;;
esac

export DVRTC_VERSION="$VERSION"
export VCS_REF="$VCS_REF"
export DVRTC_SOURCE="${DVRTC_SOURCE:-$DEFAULT_SOURCE_URL}"

echo "Building release images for ${VERSION}"
docker compose --env-file "$ENV_FILE" --project-directory "$REPO_ROOT" -f "$BASE_COMPOSE_FILE" -f "$SCENARIO_COMPOSE_FILE" -f "$BASE_DEV_COMPOSE_FILE" -f "$SCENARIO_DEV_COMPOSE_FILE" build $SERVICES
docker compose --env-file "$ENV_FILE" --project-directory "$REPO_ROOT" -f "$BASE_COMPOSE_FILE" -f "$SCENARIO_COMPOSE_FILE" -f "$BASE_DEV_COMPOSE_FILE" -f "$SCENARIO_DEV_COMPOSE_FILE" --profile testing build "$TESTING_SERVICE"

if [ "$PUSH" -eq 1 ]; then
    echo "Pushing release images for ${VERSION}"
    docker compose --env-file "$ENV_FILE" --project-directory "$REPO_ROOT" -f "$BASE_COMPOSE_FILE" -f "$SCENARIO_COMPOSE_FILE" -f "$BASE_DEV_COMPOSE_FILE" -f "$SCENARIO_DEV_COMPOSE_FILE" push $SERVICES
    docker compose --env-file "$ENV_FILE" --project-directory "$REPO_ROOT" -f "$BASE_COMPOSE_FILE" -f "$SCENARIO_COMPOSE_FILE" -f "$BASE_DEV_COMPOSE_FILE" -f "$SCENARIO_DEV_COMPOSE_FILE" --profile testing push "$TESTING_SERVICE"
fi
