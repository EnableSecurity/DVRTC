#!/bin/sh

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

IMAGE_PREFIX="ghcr.io/enablesecurity/dvrtc"
COMPOSE_FILE="$REPO_ROOT/docker-compose.yml"
VERSION_FILE=""

usage() {
    cat <<'EOF'
Usage:
  ./scripts/validate_image_refs.sh [options]

Options:
  --compose-file PATH  Validate the specified compose file
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

awk '
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
        print service "\t" image
    }
' "$COMPOSE_FILE" > "$TMP_FILE"

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

errors=0

extract_image_for_service() {
    SERVICE="$1"
    awk -F '\t' -v service="$SERVICE" '$1 == service { print $2 }' "$TMP_FILE"
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

echo "Image reference validation passed for $COMPOSE_FILE"
