#!/bin/bash

if [[ -f "${WORKDIR}/.dev/utility.sh" ]]; then
    . "${WORKDIR}/.dev/utility.sh"
fi

if [[ -f ~/.bashrc ]]; then
    . ~/.bashrc
fi

# generic
alias ll="ls -al"

alias app="cd ${WORKDIR}"

alias full="clear && scomposer install && pfix && punit && pstan"
# end generic

# git
git config --global --add safe.directory "${WORKDIR}"
# end git

# composer
scomposer() {
    if [[ -e 'composer.json' ]]; then
        print_command "composer $@"
        composer "$@"
    else
        print_error 'composer json not found'
        return 0
    fi
}

alias ci="clear && scomposer install"
alias cu="clear && scomposer update"
# end composer

pfix() {
    if [[ -e "${PWD}/vendor/bin/php-cs-fixer" ]]; then
        EXEC_PATH="${PWD}/vendor/bin/php-cs-fixer"
    else
        print_error 'php cs fixer not found'
        return 0
    fi

    print_command "PHP_CS_FIXER_IGNORE_ENV=1 php -d memory_limit=-1 ${EXEC_PATH} fix $@"
    PHP_CS_FIXER_IGNORE_ENV=1 php -d memory_limit=-1 "${EXEC_PATH}" fix "$@"

    return 0
}

punit() {
    if [[ -e "${PWD}/vendor/bin/simple-phpunit" ]]; then
        EXEC_PATH="${PWD}/vendor/bin/simple-phpunit"
    else
        print_error 'phpunit not found'
        return 0
    fi

    print_command "php -d memory_limit=-1 ${EXEC_PATH} $@"
    php -d memory_limit=-1 "${EXEC_PATH}" "$@"

    return 0
}

pstan() {
    if [[ -e "${PWD}/vendor/bin/phpstan" ]]; then
        EXEC_PATH="${PWD}/vendor/bin/phpstan"
    else
        print_error 'phpstan not found'
        return 0
    fi

    print_command "php -d memory_limit=-1 ${EXEC_PATH} analyse $@"
    php -d memory_limit=-1 "${EXEC_PATH}" analyse "$@"

    return 0
}

if [[ -f ~/.profile_local ]]; then
    . ~/.profile_local
fi
