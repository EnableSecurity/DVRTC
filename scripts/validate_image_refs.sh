#!/bin/sh

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="$REPO_ROOT/.env"
PROJECT_DIRECTORY="$REPO_ROOT"

IMAGE_PREFIX="ghcr.io/enablesecurity/dvrtc"
COMPOSE_FILE="$REPO_ROOT/compose/base.yml"
SCENARIO_COMPOSE_FILE=""
VERSION_FILE=""
SCENARIO="pbx1"

usage() {
    cat <<'EOF'
Usage:
  ./scripts/validate_image_refs.sh [options]

Options:
  --compose-file PATH  Validate the specified compose file
  --scenario NAME     Validate service references for pbx1 or pbx2
  --version-file PATH  Read the expected DVRTC version from PATH
  -h, --help           Show this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --compose-file)
            if [ $# -lt 2 ]; then
                echo "ERROR: --compose-file requires a value" >&2
                exit 1
            fi
            COMPOSE_FILE="$2"
            shift 2
            ;;
        --version-file)
            if [ $# -lt 2 ]; then
                echo "ERROR: --version-file requires a value" >&2
                exit 1
            fi
            VERSION_FILE="$2"
            shift 2
            ;;
        --scenario)
            SCENARIO="$2"
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

case "$COMPOSE_FILE" in
    /*) ;;
    *) COMPOSE_FILE="$(cd "$PWD" && pwd)/$COMPOSE_FILE" ;;
esac

if [ ! -f "$COMPOSE_FILE" ]; then
    echo "ERROR: Compose file not found: $COMPOSE_FILE" >&2
    exit 1
fi

if [ -z "$SCENARIO_COMPOSE_FILE" ]; then
    SCENARIO_COMPOSE_FILE="$(dirname "$COMPOSE_FILE")/${SCENARIO}.yml"
fi

if [ ! -f "$SCENARIO_COMPOSE_FILE" ]; then
    echo "ERROR: Scenario compose file not found: $SCENARIO_COMPOSE_FILE" >&2
    exit 1
fi

if [ "$(basename "$(dirname "$COMPOSE_FILE")")" = "compose" ]; then
    PROJECT_DIRECTORY="$(cd "$(dirname "$COMPOSE_FILE")/.." && pwd)"
fi

if [ -z "$VERSION_FILE" ]; then
    CANDIDATE_VERSION_FILE="$(dirname "$COMPOSE_FILE")/VERSION"
    if [ -f "$CANDIDATE_VERSION_FILE" ]; then
        VERSION_FILE="$CANDIDATE_VERSION_FILE"
    else
        VERSION_FILE="$REPO_ROOT/VERSION"
    fi
fi

if [ ! -f "$VERSION_FILE" ]; then
    echo "ERROR: Version file not found: $VERSION_FILE" >&2
    exit 1
fi

EXPECTED_VERSION="$(tr -d '\n' < "$VERSION_FILE")"
TMP_FILE="$(mktemp)"
cleanup() {
    rm -f "$TMP_FILE"
}
trap cleanup EXIT INT TERM

if [ -f "$ENV_FILE" ]; then
    PUBLIC_IPV4=127.0.0.1 \
    MYSQL_ROOT_PASSWORD=dvrtc-validate \
    SIPCALLER1_PASSWORD=dvrtc-validate \
    docker compose --env-file "$ENV_FILE" --project-directory "$PROJECT_DIRECTORY" -f "$COMPOSE_FILE" -f "$SCENARIO_COMPOSE_FILE" --profile testing config > "$TMP_FILE"
else
    PUBLIC_IPV4=127.0.0.1 \
    MYSQL_ROOT_PASSWORD=dvrtc-validate \
    SIPCALLER1_PASSWORD=dvrtc-validate \
    docker compose --project-directory "$PROJECT_DIRECTORY" -f "$COMPOSE_FILE" -f "$SCENARIO_COMPOSE_FILE" --profile testing config > "$TMP_FILE"
fi

case "$SCENARIO" in
    pbx1)
        expected_services="
asterisk
rtpengine
kamailio
baresip-callgen
baresip-callgen-b
baresip-callgen-c
baresip-digestleak
nginx
voicemailcleaner
mysqlclient
dbcleaner
db
testing
attacker
certbot
coturn
"
        ;;
    pbx2)
        expected_services="
freeswitch
rtpproxy
opensips
baresip-callgen-pbx2
baresip-callgen-b-pbx2
baresip-callgen-c-pbx2
baresip-digestleak-pbx2
nginx-pbx2
recordingscleaner
testing
attacker
certbot
"
        ;;
    *)
        echo "ERROR: Unknown scenario: $SCENARIO" >&2
        exit 1
        ;;
esac

errors=0

extract_image_for_service() {
    SERVICE="$1"
    awk -v service_name="$SERVICE" '
        BEGIN { in_services = 0; service = "" }
        /^services:/ { in_services = 1; next }
        in_services && /^[^[:space:]]/ { in_services = 0 }
        in_services && /^  [A-Za-z0-9_.-]+:/ {
            service = $1
            sub(/:$/, "", service)
            next
        }
        in_services && /^    image:[[:space:]]*/ {
            image = $0
            sub(/^    image:[[:space:]]*/, "", image)
            if (service == service_name) {
                print image
            }
        }
    ' "$TMP_FILE"
}

extract_tag() {
    REF="${1%@*}"
    LAST_SEGMENT="${REF##*/}"
    case "$LAST_SEGMENT" in
        *:*) printf '%s\n' "${LAST_SEGMENT##*:}" ;;
        *) return 1 ;;
    esac
}

is_repo_owned_image() {
    REF="${1%@*}"
    case "$REF" in
        "$IMAGE_PREFIX"/*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

for service in $expected_services; do
    image="$(extract_image_for_service "$service")"
    if [ -z "$image" ]; then
        echo "ERROR: Service '$service' is missing an image reference" >&2
        errors=$((errors + 1))
        continue
    fi

    if ! tag="$(extract_tag "$image")"; then
        echo "ERROR: Service '$service' uses an untagged image: $image" >&2
        errors=$((errors + 1))
        continue
    fi

    if [ "$tag" = "latest" ]; then
        echo "ERROR: Service '$service' uses :latest, which is not allowed: $image" >&2
        errors=$((errors + 1))
    fi

    if is_repo_owned_image "$image" && [ "$tag" != "$EXPECTED_VERSION" ]; then
        echo "ERROR: Service '$service' uses tag '$tag' but VERSION requires '$EXPECTED_VERSION': $image" >&2
        errors=$((errors + 1))
    fi
done

if [ "$errors" -ne 0 ]; then
    echo "Image reference validation failed with $errors error(s)." >&2
    exit 1
fi

echo "Image reference validation passed for $COMPOSE_FILE + $SCENARIO_COMPOSE_FILE"
