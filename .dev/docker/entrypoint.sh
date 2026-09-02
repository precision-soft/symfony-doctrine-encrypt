#!/bin/bash
set -e

source "${HOME}/.profile"

echo "boot started with path ${WORKDIR}"

cd "${WORKDIR}"

LOCK_HASH=""
LOCK_HASH_FILE="${WORKDIR}/vendor/.composer.lock.md5"

if [[ -f "composer.lock" ]]; then
    LOCK_HASH=$(md5sum composer.lock | cut -d ' ' -f 1)
fi

if [[ -f "vendor/autoload.php" ]] && [[ -f "${LOCK_HASH_FILE}" ]] && [[ "${LOCK_HASH}" == "$(cat "${LOCK_HASH_FILE}")" ]]; then
    echo "vendor up to date, skipping composer install"
else
    scomposer install

    if [[ -n "${LOCK_HASH}" ]] && [[ -f "vendor/autoload.php" ]]; then
        echo "${LOCK_HASH}" > "${LOCK_HASH_FILE}"
    fi
fi

exec sleep infinity
