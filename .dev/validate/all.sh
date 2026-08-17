#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

REPOSITORY_ROOT_PATH="$(git rev-parse --show-toplevel 2> /dev/null || true)"
if [[ "" = "${REPOSITORY_ROOT_PATH}" ]]; then
    SCRIPT_PATH="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    REPOSITORY_ROOT_PATH="$(cd -P "${SCRIPT_PATH}/../.." && pwd)"
fi

cd "${REPOSITORY_ROOT_PATH}"

. "${REPOSITORY_ROOT_PATH}/.dev/utility.sh"

AUDIT_REQUESTED="false"
INTEGRATION_REQUESTED="false"
MUTATION_REQUESTED="false"
STAGED_ONLY_REQUESTED="false"

for FLAG in "$@"; do
    case "${FLAG}" in
        -h)
            println "usage: all.sh [-h] [--staged] [--audit] [--integration] [--mutation]"
            println ""
            println "  -h              show this help and exit"
            println "  --staged        do nothing unless the index carries a php change ( the pre-commit hook )"
            println "  --audit         also audit the locked dependencies for advisories ( needs: network )"
            println "  --integration   also run the integration suite ( needs: ./dc --profile db up -d )"
            println "  --mutation      also run mutation testing ( slow: it runs the suite once per mutant )"
            exit 0
            ;;
        --staged)
            STAGED_ONLY_REQUESTED="true"
            ;;
        --audit)
            AUDIT_REQUESTED="true"
            ;;
        --integration)
            INTEGRATION_REQUESTED="true"
            ;;
        --mutation)
            MUTATION_REQUESTED="true"
            ;;
        *)
            fail "unknown flag: ${FLAG}"
            ;;
    esac
done

has_staged_change() {
    if git --no-pager diff --cached --name-only --diff-filter=d | grep -qE "$1"; then
        println "true"

        return
    fi

    println "false"
}

if [[ "true" = "${STAGED_ONLY_REQUESTED}" ]] && [[ "false" = "$(has_staged_change '\.php$')" ]]; then
    exit 0
fi

require_docker
require_docker_daemon

if ! docker_compose_service_exists "${CONTAINER_DEV}"; then
    fail "missing docker compose service: ${CONTAINER_DEV}"
fi

ensure_service_running "${CONTAINER_DEV}"

run_section "cs check" "${TAG_VALIDATE}" "php" -- \
    run_in_service_shell "${CONTAINER_DEV}" "composer cs-check"

run_section "phpstan" "${TAG_VALIDATE}" "php" -- \
    run_in_service_shell "${CONTAINER_DEV}" "composer phpstan"

run_section "test" "${TAG_VALIDATE}" "php" -- \
    run_in_service_shell "${CONTAINER_DEV}" "composer test"

if [[ "true" = "${AUDIT_REQUESTED}" ]]; then
    run_section "deps audit" "${TAG_VALIDATE}" "php" -- \
        run_in_service_shell "${CONTAINER_DEV}" "composer deps-audit"
fi

if [[ "true" = "${INTEGRATION_REQUESTED}" ]]; then
    for CONTAINER_DATABASE in mysql mariadb; do
        ensure_service_running "${CONTAINER_DATABASE}"
        wait_for_service_healthy "${CONTAINER_DATABASE}"
    done

    run_section "test integration" "${TAG_VALIDATE}" "php" -- \
        run_in_service_shell "${CONTAINER_DEV}" "composer test-integration"
fi

if [[ "true" = "${MUTATION_REQUESTED}" ]]; then
    run_section "mutation" "${TAG_VALIDATE}" "php" -- \
        run_in_service_shell "${CONTAINER_DEV}" "composer mutation"
fi
