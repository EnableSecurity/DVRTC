#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "$SCRIPT_DIR/lib/compose-common.sh"
compose_common_init "$REPO_ROOT"

DEFAULT_SOURCE_URL="https://github.com/EnableSecurity/DVRTC"
SCENARIO="pbx1"
KNOWN_SERVICES=(
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
  freeswitch
  rtpproxy
  opensips
  baresip-callgen-pbx2
  baresip-callgen-b-pbx2
  baresip-callgen-c-pbx2
  baresip-digestleak-pbx2
  nginx-pbx2
  recordingscleaner
  certbot
  coturn
  testing
  attacker
)

usage() {
    cat <<'EOF'
Usage:
  ./scripts/dev-compose.sh [--scenario pbx1|pbx2] [docker compose args...]

Examples:
  ./scripts/dev-compose.sh build
  ./scripts/dev-compose.sh --scenario pbx1 up -d
  ./scripts/dev-compose.sh --scenario pbx2 up -d
  ./scripts/dev-compose.sh --profile testing build testing attacker

Defaults:
  DVRTC_VERSION defaults to the contents of VERSION
  VCS_REF defaults to the current git commit

Override DVRTC_VERSION explicitly when you intentionally want non-release metadata:
  DVRTC_VERSION=dev ./scripts/dev-compose.sh build nginx
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
        *)
            break
            ;;
    esac
done

if [ $# -eq 0 ]; then
    usage >&2
    exit 1
fi

case "$SCENARIO" in
    pbx1)
        compose_resolve_scenario "$SCENARIO"
        RUNTIME_SERVICES=(
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
          certbot
          coturn
        )
        BUILD_SERVICES=(
          asterisk
          rtpengine
          kamailio
          baresip-callgen
          baresip-digestleak
          nginx
          voicemailcleaner
          mysqlclient
          dbcleaner
          db
        )
        ;;
    pbx2)
        compose_resolve_scenario "$SCENARIO"
        RUNTIME_SERVICES=(
          freeswitch
          rtpproxy
          opensips
          baresip-callgen-pbx2
          baresip-callgen-b-pbx2
          baresip-callgen-c-pbx2
          baresip-digestleak-pbx2
          nginx-pbx2
          recordingscleaner
          certbot
        )
        BUILD_SERVICES=(
          freeswitch
          rtpproxy
          opensips
          baresip-callgen-pbx2
          baresip-digestleak-pbx2
          nginx-pbx2
        )
        ;;
    *)
        echo "ERROR: Unknown scenario: $SCENARIO" >&2
        usage >&2
        exit 1
        ;;
esac

VERSION="$(tr -d '\n' < "$REPO_ROOT/VERSION")"
VCS_REF_DEFAULT="unknown"
if git -C "$REPO_ROOT" rev-parse --short=12 HEAD >/dev/null 2>&1; then
    VCS_REF_DEFAULT="$(git -C "$REPO_ROOT" rev-parse --short=12 HEAD)"
fi

export DVRTC_VERSION="${DVRTC_VERSION:-$VERSION}"
export VCS_REF="${VCS_REF:-$VCS_REF_DEFAULT}"
export DVRTC_SOURCE="${DVRTC_SOURCE:-$DEFAULT_SOURCE_URL}"

compose_cmd=(
  docker compose
  --env-file "$ENV_FILE"
  --project-directory "$PROJECT_DIRECTORY"
  -p "$PROJECT_NAME"
  -f "$BASE_COMPOSE_FILE"
  -f "$SCENARIO_COMPOSE_FILE"
  -f "$BASE_DEV_COMPOSE_FILE"
  -f "$SCENARIO_DEV_COMPOSE_FILE"
)

args=("$@")
compose_extract_subcommand "$@"
subcommand="$COMPOSE_SUBCOMMAND"
subcommand_index=-1
for i in "${!args[@]}"; do
    if [ "${args[$i]}" = "$subcommand" ]; then
        subcommand_index=$i
        break
    fi
done

if [ "$subcommand" = "up" ] || [ "$subcommand" = "start" ] || [ "$subcommand" = "restart" ]; then
    compose_cleanup_other_scenarios 1
fi

explicit_service=0
for token in "${args[@]:$((subcommand_index + 1))}"; do
    for service in "${KNOWN_SERVICES[@]}"; do
        if [ "$token" = "$service" ]; then
            explicit_service=1
            break
        fi
    done
    if [ "$explicit_service" -eq 1 ]; then
        break
    fi
done

run_service=""
if [ "$subcommand" = "run" ]; then
    skip_next=0
    for token in "${args[@]:$((subcommand_index + 1))}"; do
        if [ "$skip_next" -eq 1 ]; then
            skip_next=0
            continue
        fi
        case "$token" in
            -e|--env|--entrypoint|--name|-p|--publish|-u|--user|-v|--volume|-w|--workdir|-l|--label|--pull|--cap-add|--cap-drop)
                skip_next=1
                ;;
            --env=*|--entrypoint=*|--name=*|--publish=*|--user=*|--volume=*|--workdir=*|--label=*|--pull=*|--cap-add=*|--cap-drop=*)
                ;;
            -*)
                ;;
            *)
                run_service="$token"
                break
                ;;
        esac
    done
fi

FINAL_ARGS=("${args[@]}")
if [ "$subcommand" = "run" ] && { [ "$run_service" = "testing" ] || [ "$run_service" = "attacker" ]; }; then
    FINAL_ARGS=(
      "${args[@]:0:$((subcommand_index + 1))}"
      -e "SCENARIO=${SCENARIO}"
      "${args[@]:$((subcommand_index + 1))}"
    )
fi
compose_append_remove_orphans_for_up

if [ -n "$subcommand" ] && [ "$explicit_service" -eq 0 ]; then
    case "$subcommand" in
        up|pull|start|stop|restart|rm|logs|ps)
            exec "${compose_cmd[@]}" "${FINAL_ARGS[@]}" "${RUNTIME_SERVICES[@]}"
            ;;
        build|push)
            exec "${compose_cmd[@]}" "${FINAL_ARGS[@]}" "${BUILD_SERVICES[@]}"
            ;;
    esac
fi

exec "${compose_cmd[@]}" "${FINAL_ARGS[@]}"
