#!/bin/bash

if [[ -f /var/www/html/dev/utility.sh ]]; then
    . /var/www/html/dev/utility.sh
fi

if [[ -f ~/.bashrc ]]; then
    . ~/.bashrc
fi

# generic
alias ll="ls -al"

alias app="cd /var/www/html"

alias full="clear && scomposer install && pfix && punit && pstan"
# end generic

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

if [[ -f ~/.profile_local ]]; then
    . ~/.profile_local
fi
