#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SCENARIO="pbx1"
BASE_COMPOSE_FILE="$REPO_ROOT/compose/base.yml"
ENV_FILE="$REPO_ROOT/.env"

while [ $# -gt 0 ]; do
    case "$1" in
        --scenario)
            SCENARIO="${2:?missing scenario}"
            shift 2
            ;;
        --scenario=*)
            SCENARIO="${1#*=}"
            shift
            ;;
        *)
            break
            ;;
    esac
done

case "$SCENARIO" in
    pbx1|pbx2)
        ;;
    *)
        echo "ERROR: Unknown scenario: $SCENARIO" >&2
        exit 1
        ;;
esac

cd "${REPO_ROOT}"

exec docker compose \
    --env-file "$ENV_FILE" \
    --project-directory "$REPO_ROOT" \
    -p "dvrtc-${SCENARIO}" \
    -f "$BASE_COMPOSE_FILE" \
    -f "$REPO_ROOT/compose/${SCENARIO}.yml" \
    run --rm -e SCENARIO="${SCENARIO}" attacker attacker-run-all "$@"
