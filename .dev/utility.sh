#!/bin/bash

if [[ $TERM == *color* ]]; then
    COLOR_RESET='\e[0;0m'
    COLOR_GREEN='\e[0;32m'
    COLOR_YELLOW='\e[0;33m'
    COLOR_RED='\e[0;31m'
else
    COLOR_RESET=''
    COLOR_GREEN=''
    COLOR_YELLOW=''
    COLOR_RED=''
fi

DOCKER_PATH=".dev/docker/"
DEV_DATA_PATH=".dev-data/"
CONTAINER_DEV="dev"

TAG_DOCKER="docker"
TAG_GIT="git"
TAG_VALIDATE="validate"

warning() {
    println "${COLOR_YELLOW}( $1 )${COLOR_RESET}"
}

info() {
    println "${COLOR_YELLOW}[ info ][ $1 ]${COLOR_RESET}"
}

success() {
    println "${COLOR_GREEN}[ success ][ $1 ]${COLOR_RESET}"
}

fail() {
    error "$1"

    exit 1
}

section() {
    println "${COLOR_YELLOW}[[${COLOR_GREEN} $1 ${COLOR_YELLOW}]]${COLOR_RESET}"
}

print_command() {
    println "${COLOR_YELLOW}[${COLOR_GREEN} $1 ${COLOR_YELLOW}]${COLOR_RESET}"
}

println() {
    printf %b "$1\n"
}

error() {
    println "${COLOR_RED}( $1 )${COLOR_RESET}"
}

print_error() {
    error "$1"
}

run_in_container() {
    bash "${PWD}/dc" exec -T "$@"
}

run_in_container_dev() {
    run_in_container "${CONTAINER_DEV}" "$@"
}

error_container() {
    echo "the '$1' container is not running"
}

check_container() {
    CONTAINER_NAME="$1"

    if [[ $(docker_compose_no_log ps -q "${CONTAINER_NAME}") = "" ]]; then
        echo 1
        return
    fi

    echo 0
}

ensure_container_dev() {
    if [[ $(check_container "${CONTAINER_DEV}") != 0 ]]; then
        warning "the '${CONTAINER_DEV}' container is not running ( starting )"

        docker_compose up -d "${CONTAINER_DEV}"
    fi
}

docker_compose_no_log() {
    (
        cd "${DOCKER_PATH}" &&
        USER_ID=$(id -u) GROUP_ID=$(id -g) docker compose --env-file .env --env-file .env.local "$@"
    )
}

docker_compose() {
    local IFS=' '

    print_command "(cd ${DOCKER_PATH} && USER_ID=$(id -u) GROUP_ID=$(id -g) docker compose --env-file .env --env-file .env.local $*)"

    docker_compose_no_log "$@"
}

require_command() {
    COMMAND_NAME="$1"

    if ! command -v "${COMMAND_NAME}" > /dev/null 2>&1; then
        fail "${COMMAND_NAME} is not available"
    fi
}

require_docker() {
    require_command docker
}

require_docker_daemon() {
    if ! docker info > /dev/null 2>&1; then
        fail "docker daemon is not reachable"
    fi
}

docker_compose_service_exists() {
    SERVICE_NAME="$1"

    if docker_compose_no_log config --services 2> /dev/null | grep -Fxq "${SERVICE_NAME}"; then
        return 0
    fi

    return 1
}

ensure_service_running() {
    SERVICE_NAME="$1"

    if [[ $(docker_compose_no_log ps -q "${SERVICE_NAME}" 2> /dev/null) = "" ]]; then
        info "the '${SERVICE_NAME}' container is not running ( starting )"

        docker_compose up -d "${SERVICE_NAME}"
    fi
}

wait_for_service_healthy() {
    SERVICE_NAME="$1"
    TIMEOUT_SECONDS="${2:-90}"

    CONTAINER_ID="$(docker_compose_no_log ps -q "${SERVICE_NAME}" 2> /dev/null)"

    if [[ "" = "${CONTAINER_ID}" ]]; then
        fail "the '${SERVICE_NAME}' container is not running"
    fi

    WAITED_SECONDS=0

    while true; do
        HEALTH_STATUS="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "${CONTAINER_ID}" 2> /dev/null)"

        if [[ "healthy" = "${HEALTH_STATUS}" || "none" = "${HEALTH_STATUS}" ]]; then
            return 0
        fi

        if [[ "${WAITED_SECONDS}" -ge "${TIMEOUT_SECONDS}" ]]; then
            fail "the '${SERVICE_NAME}' container is still '${HEALTH_STATUS}' after ${TIMEOUT_SECONDS}s"
        fi

        if [[ 0 -eq "${WAITED_SECONDS}" ]]; then
            info "waiting for the '${SERVICE_NAME}' container to become healthy"
        fi

        sleep 2

        WAITED_SECONDS=$((WAITED_SECONDS + 2))
    done
}

run_in_service_shell() {
    SERVICE_NAME="$1"
    COMMAND_STRING="$2"

    ensure_service_running "${SERVICE_NAME}"

    docker_compose exec -T "${SERVICE_NAME}" bash -c "${COMMAND_STRING}" < /dev/null
}

run_section() {
    local IFS=' '

    TITLE=""
    TAG_LIST=()
    COMMAND_LIST=()
    FOUND_DELIMITER=1

    for ARGUMENT in "$@"; do
        if [[ "${TITLE}" = "" ]]; then
            TITLE="${ARGUMENT}"
            continue
        fi

        if [[ ${FOUND_DELIMITER} != 0 ]]; then
            if [[ "${ARGUMENT}" = "--" ]]; then
                FOUND_DELIMITER=0
                continue
            fi

            TAG_LIST+=("${ARGUMENT}")
            continue
        fi

        COMMAND_LIST+=("${ARGUMENT}")
    done

    if [[ ${FOUND_DELIMITER} != 0 ]] || [[ ${#COMMAND_LIST[@]} = 0 ]]; then
        fail "run_section requires: TITLE [TAGS...] -- COMMAND..."
    fi

    section "${TITLE} ${TAG_LIST[*]} start"

    EXIT_CODE=0
    "${COMMAND_LIST[@]}" || EXIT_CODE=$?

    if [[ ${EXIT_CODE} = 0 ]]; then
        success "${TITLE} ${TAG_LIST[*]} end"

        return 0
    fi

    error "${TITLE} ${TAG_LIST[*]} end failed"

    return ${EXIT_CODE}
}

ensure_dev_data_directories() {
    for DEV_DATA_DIRECTORY in "${DEV_DATA_PATH}composer"; do
        if [[ ! -d "${DEV_DATA_DIRECTORY}" ]]; then
            mkdir -p "${DEV_DATA_DIRECTORY}"
        fi
    done
}
