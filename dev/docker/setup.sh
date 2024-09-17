#!/bin/bash
set -e

source ${HOME}/.profile

echo "boot started with path ${WORKDIR}"

cd ${WORKDIR}

INITIAL_SETUP_MARKER="/setup.initial.done"
if [[ ! -e ${INITIAL_SETUP_MARKER} ]]; then
    echo 'Initial setup starting ...'

    scomposer install

    echo 'Initial setup done'

    touch ${INITIAL_SETUP_MARKER}
else
    echo 'Already setup'
fi

sleep infinity
