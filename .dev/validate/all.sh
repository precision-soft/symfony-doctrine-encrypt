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
EXAMPLE_REQUESTED="false"
INTEGRATION_REQUESTED="false"
MUTATION_REQUESTED="false"
STAGED_ONLY_REQUESTED="false"

for FLAG in "$@"; do
    case "${FLAG}" in
        -h)
            println "usage: all.sh [-h] [--staged] [--audit] [--example] [--integration] [--mutation]"
            println ""
            println "  -h              show this help and exit"
            println "  --staged        run only the sections the index touches ( the pre-commit hook )"
            println "  --audit         also audit the locked dependencies for advisories ( needs: network )"
            println "  --example       also run the example application's gate ( skipped with a notice when .example/composer.json is absent )"
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
        --example)
            EXAMPLE_REQUESTED="true"
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

RUN_PHP_SECTIONS="true"
RUN_EXAMPLE_SECTION="${EXAMPLE_REQUESTED}"

if [[ "true" = "${STAGED_ONLY_REQUESTED}" ]]; then
    RUN_PHP_SECTIONS="$(has_staged_change '\.php$')"
    RUN_EXAMPLE_SECTION="$(has_staged_change '^\.example/')"

    if [[ "false" = "${RUN_PHP_SECTIONS}" ]] && [[ "false" = "${RUN_EXAMPLE_SECTION}" ]]; then
        exit 0
    fi
fi

require_docker
require_docker_daemon

if ! docker_compose_service_exists "${CONTAINER_DEV}"; then
    fail "missing docker compose service: ${CONTAINER_DEV}"
fi

ensure_service_running "${CONTAINER_DEV}"

if [[ "true" = "${RUN_PHP_SECTIONS}" ]]; then
    run_section "cs check" "${TAG_VALIDATE}" "php" -- \
        run_in_service_shell "${CONTAINER_DEV}" "composer cs-check"

    run_section "phpstan" "${TAG_VALIDATE}" "php" -- \
        run_in_service_shell "${CONTAINER_DEV}" "composer phpstan"

    run_section "test" "${TAG_VALIDATE}" "php" -- \
        run_in_service_shell "${CONTAINER_DEV}" "composer test"
fi

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

if [[ "true" = "${RUN_EXAMPLE_SECTION}" ]]; then
    if [[ -f ".example/composer.json" ]]; then
        for CONTAINER_DATABASE in mysql mariadb; do
            ensure_service_running "${CONTAINER_DATABASE}"
            wait_for_service_healthy "${CONTAINER_DATABASE}"
        done

        run_section "example" "${TAG_VALIDATE}" "php" -- \
            run_in_service_shell "${CONTAINER_DEV}" "cd .example && composer install --no-interaction --no-progress && composer check"
    else
        info "skip example ( no .example/composer.json in this repository )"
    fi
fi

if [[ "true" = "${MUTATION_REQUESTED}" ]]; then
    run_section "mutation" "${TAG_VALIDATE}" "php" -- \
        run_in_service_shell "${CONTAINER_DEV}" "composer mutation"
fi
