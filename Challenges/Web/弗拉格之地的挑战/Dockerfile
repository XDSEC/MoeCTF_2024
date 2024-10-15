FROM ctftraining/base_image_nginx_mysql_php_73

COPY src /tmp

RUN cp -rf /tmp/html /var/www/ \
    && chown -R www-data:www-data /var/www/html \
    && cp -f /tmp/flag7 /flag7 \
    && cp -f /tmp/hint.txt /hint.txt
