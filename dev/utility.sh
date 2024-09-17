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

DOCKER_PATH="dev/docker/"
CONTAINER_DEV="dev"

error() {
    println "${COLOR_RED}( $1 )${COLOR_RESET}"
}

warning() {
    println "${COLOR_YELLOW}( $1 )${COLOR_RESET}"
}

section() {
    println "${COLOR_YELLOW}[[${COLOR_GREEN} $1 ${COLOR_YELLOW}]]${COLOR_RESET}"
}

print_command() {
    println "${COLOR_YELLOW}[${COLOR_GREEN} $1 ${COLOR_YELLOW}]${COLOR_RESET}"
}

print_error() {
    println "${COLOR_RED}( $1 )${COLOR_RESET}"
}

println() {
    printf %b "$1\n"
}

run_in_container() {
    bash ${PWD}/dc exec -T "$@"
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
    fi

    echo 0
}

docker_compose_no_log() {
    (
        cd ${DOCKER_PATH} &&
        USER_ID=$(id -u) GROUP_ID=$(id -g) docker compose --env-file .env --env-file .env.local "$@"
    )
}

docker_compose() {
    print_command "(cd ${DOCKER_PATH} && USER_ID=$(id -u) GROUP_ID=$(id -g) docker compose --env-file .env --env-file .env.local $*)"

    docker_compose_no_log "$@"
}
