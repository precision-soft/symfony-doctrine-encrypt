#!/bin/bash
set -e
# set -x

source "${HOME}/.profile"

echo "boot started with path ${WORKDIR}"

cd "${WORKDIR}"

scomposer install || echo "[WARNING] composer install failed" >&2

sleep infinity
