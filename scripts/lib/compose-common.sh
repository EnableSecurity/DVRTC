#!/bin/bash

compose_common_init() {
    local repo_root="$1"

    COMPOSE_REPO_ROOT="$repo_root"
    COMPOSE_DIR="$repo_root/compose"
    ENV_FILE="$repo_root/.env"
    PROJECT_DIRECTORY="$repo_root"
    BASE_COMPOSE_FILE="$COMPOSE_DIR/base.yml"
    BASE_DEV_COMPOSE_FILE="$COMPOSE_DIR/dev.yml"
}

compose_resolve_scenario() {
    local scenario="$1"

    case "$scenario" in
        pbx1|pbx2)
            SCENARIO="$scenario"
            SCENARIO_COMPOSE_FILE="$COMPOSE_DIR/${scenario}.yml"
            SCENARIO_DEV_COMPOSE_FILE="$COMPOSE_DIR/dev.${scenario}.yml"
            PROJECT_NAME="dvrtc-${scenario}"
            if [ "$scenario" = "pbx1" ]; then
                OTHER_SCENARIO="pbx2"
            else
                OTHER_SCENARIO="pbx1"
            fi
            OTHER_PROJECT_NAME="dvrtc-${OTHER_SCENARIO}"
            OTHER_COMPOSE_FILE="$COMPOSE_DIR/${OTHER_SCENARIO}.yml"
            OTHER_SCENARIO_DEV_COMPOSE_FILE="$COMPOSE_DIR/dev.${OTHER_SCENARIO}.yml"
            ;;
        *)
            echo "ERROR: Unknown scenario: $scenario" >&2
            return 1
            ;;
    esac
}

compose_extract_subcommand() {
    local skip_next=0
    local token

    COMPOSE_SUBCOMMAND=""
    for token in "$@"; do
        if [ "$skip_next" -eq 1 ]; then
            skip_next=0
            continue
        fi
        case "$token" in
            --profile|--file|-f|--project-name|-p|--env-file)
                skip_next=1
                ;;
            --profile=*|--file=*|--project-name=*|--env-file=*)
                ;;
            -*)
                ;;
            *)
                COMPOSE_SUBCOMMAND="$token"
                return 0
                ;;
        esac
    done
}

compose_append_remove_orphans_for_up() {
    local token

    if [ "${COMPOSE_SUBCOMMAND:-}" != "up" ]; then
        return 0
    fi

    for token in "${FINAL_ARGS[@]}"; do
        if [ "$token" = "--remove-orphans" ]; then
            return 0
        fi
    done

    FINAL_ARGS+=("--remove-orphans")
}

compose_cleanup_other_scenarios() {
    local include_dev="${1:-0}"
    local other_compose_cmd=(
        docker compose
        --env-file "$ENV_FILE"
        --project-directory "$PROJECT_DIRECTORY"
        -p "$OTHER_PROJECT_NAME"
        -f "$BASE_COMPOSE_FILE"
        -f "$OTHER_COMPOSE_FILE"
    )
    local legacy_current_compose_cmd=(
        docker compose
        --env-file "$ENV_FILE"
        --project-directory "$PROJECT_DIRECTORY"
        -p "dvrtc"
        -f "$BASE_COMPOSE_FILE"
        -f "$SCENARIO_COMPOSE_FILE"
    )
    local legacy_other_compose_cmd=(
        docker compose
        --env-file "$ENV_FILE"
        --project-directory "$PROJECT_DIRECTORY"
        -p "dvrtc"
        -f "$BASE_COMPOSE_FILE"
        -f "$OTHER_COMPOSE_FILE"
    )

    if [ "$include_dev" = "1" ]; then
        other_compose_cmd+=(-f "$BASE_DEV_COMPOSE_FILE" -f "$OTHER_SCENARIO_DEV_COMPOSE_FILE")
        legacy_current_compose_cmd+=(-f "$BASE_DEV_COMPOSE_FILE" -f "$SCENARIO_DEV_COMPOSE_FILE")
        legacy_other_compose_cmd+=(-f "$BASE_DEV_COMPOSE_FILE" -f "$OTHER_SCENARIO_DEV_COMPOSE_FILE")
    fi

    "${other_compose_cmd[@]}" down --remove-orphans >/dev/null 2>&1 || true
    "${legacy_current_compose_cmd[@]}" down --remove-orphans >/dev/null 2>&1 || true
    "${legacy_other_compose_cmd[@]}" down --remove-orphans >/dev/null 2>&1 || true
}
