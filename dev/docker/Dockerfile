FROM php:8.2-cli-alpine

ARG CONFIG_PATH
ARG USER_ID
ARG GROUP_ID
ARG WORKDIR
ARG SETUP_SH_SOURCE

ENV USER=www-data
ENV HOME=/home/${USER}
ENV WORKDIR=${WORKDIR}

COPY ${CONFIG_PATH}/.profile* ${HOME}/
ENV ENV="${HOME}/.profile"

RUN apk add --no-cache shadow bash
RUN rm -rf /tmp/*

RUN cp $PHP_INI_DIR/php.ini-production $PHP_INI_DIR/php.ini

COPY --from=composer:latest /usr/bin/composer /usr/local/bin/composer

RUN groupmod -g ${GROUP_ID} ${USER} \
    && usermod -u ${USER_ID} ${USER}

WORKDIR ${WORKDIR}

ENV SETUP_SH=/setup.sh
COPY ${SETUP_SH_SOURCE} ${SETUP_SH}

ENTRYPOINT exec ${SETUP_SH}
