ARG PHP_VERSION=8.4

FROM php:${PHP_VERSION}-cli-alpine

ARG CONFIG_PATH
ARG USER_ID
ARG GROUP_ID
ARG WORKDIR

ENV USER=www-data
ENV HOME=/home/${USER}
ENV WORKDIR=${WORKDIR}

RUN apk add --no-cache shadow bash git && rm -rf /tmp/*

RUN cp ${PHP_INI_DIR}/php.ini-production ${PHP_INI_DIR}/php.ini

RUN docker-php-ext-install pdo_mysql

ARG PCOV_VERSION=1.0.12
RUN apk add --no-cache --virtual .build-deps ${PHPIZE_DEPS} \
    && curl -fsSL "https://github.com/krakjoe/pcov/archive/refs/tags/v${PCOV_VERSION}.tar.gz" -o /tmp/pcov.tar.gz \
    && mkdir -p /tmp/pcov \
    && tar -xzf /tmp/pcov.tar.gz -C /tmp/pcov --strip-components=1 \
    && cd /tmp/pcov \
    && phpize \
    && ./configure \
    && make -j"$(nproc)" \
    && make install \
    && docker-php-ext-enable pcov \
    && php -m | grep -qx pcov \
    && apk del .build-deps \
    && rm -rf /tmp/*

ARG INFECTION_VERSION=0.35.3
ARG INFECTION_VERSION_PHP_8_2=0.31.9
RUN if [ "$(php -r 'echo PHP_VERSION_ID < 80300 ? 1 : 0;')" = 1 ]; then INFECTION_VERSION="${INFECTION_VERSION_PHP_8_2}"; fi \
    && curl -fsSL -o /usr/local/bin/infection \
        "https://github.com/infection/infection/releases/download/${INFECTION_VERSION}/infection.phar" \
    && chmod +x /usr/local/bin/infection \
    && infection --version \
    && rm -rf /tmp/*

COPY ${CONFIG_PATH}/php.dev.ini ${PHP_INI_DIR}/conf.d/zz-dev.ini

COPY --from=composer:latest /usr/bin/composer /usr/local/bin/composer

RUN groupmod -g ${GROUP_ID} ${USER} \
    && usermod -u ${USER_ID} ${USER}

COPY ${CONFIG_PATH}/.profile* ${HOME}/
ENV ENV="${HOME}/.profile"
RUN printf '%s\n' \
        'if [ -f "$HOME/.profile" ]; then' \
        '    . "$HOME/.profile"' \
        'fi' \
        > "${HOME}/.bashrc" \
    && printf '%s\n' \
        'if [ -f "$HOME/.bashrc" ]; then' \
        '    . "$HOME/.bashrc"' \
        'fi' \
        > "${HOME}/.bash_profile"

WORKDIR ${WORKDIR}

COPY ${CONFIG_PATH}/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
