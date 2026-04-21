#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "$SCRIPT_DIR/lib/compose-common.sh"
compose_common_init "$REPO_ROOT"
SCENARIO=""

usage() {
    cat <<'EOF'
Usage:
  ./scripts/compose.sh --scenario pbx1|pbx2 [docker compose args...]

Examples:
  ./scripts/compose.sh --scenario pbx1 up -d
  ./scripts/compose.sh --scenario pbx2 up -d
  ./scripts/compose.sh --scenario pbx1 ps
  ./scripts/compose.sh --scenario pbx2 logs opensips

Notes:
  - This is the end-user runtime wrapper.
  - It selects compose/base.yml plus compose/<scenario>.yml automatically.
  - On up/start/restart, it stops the other scenario first so host-port conflicts
    do not block startup.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --scenario)
            SCENARIO="${2:-}"
            shift 2
            ;;
        --scenario=*)
            SCENARIO="${1#*=}"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            break
            ;;
    esac
done

if [ -z "$SCENARIO" ]; then
    echo "ERROR: Scenario is required." >&2
    usage >&2
    exit 1
fi

compose_resolve_scenario "$SCENARIO" || {
    usage >&2
    exit 1
}

if [ $# -eq 0 ]; then
    usage >&2
    exit 1
fi

compose_cmd=(docker compose --env-file "$ENV_FILE" --project-directory "$PROJECT_DIRECTORY" -p "$PROJECT_NAME" -f "$BASE_COMPOSE_FILE" -f "$SCENARIO_COMPOSE_FILE")
FINAL_ARGS=("$@")
compose_extract_subcommand "$@"

if [ "$COMPOSE_SUBCOMMAND" = "up" ] || [ "$COMPOSE_SUBCOMMAND" = "start" ] || [ "$COMPOSE_SUBCOMMAND" = "restart" ]; then
    compose_cleanup_other_scenarios
fi

compose_append_remove_orphans_for_up

cd "$REPO_ROOT"
exec "${compose_cmd[@]}" "${FINAL_ARGS[@]}"
