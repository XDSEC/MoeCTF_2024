FROM php:8-fpm-alpine

LABEL authors="xt"

RUN apk add --no-cache shadow nginx && \
    usermod -u 1000 www-data && \
    groupmod -g 1000 www-data && \
    ln -sf /dev/stdout /var/log/nginx/access.log && \
    ln -sf /dev/stderr /var/log/nginx/error.log

COPY php.ini /usr/local/etc/php/conf.d/php.ini
COPY nginx.conf /etc/nginx/http.d/default.conf
COPY --chown=www-data:www-data index.php index.html /var/www/html/
COPY init.sh /init.sh
RUN chmod +x /init.sh

CMD ["/init.sh"]