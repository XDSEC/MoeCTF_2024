FROM ctftraining/base_image_nginx_mysql_php_73

COPY src /tmp

RUN cp -rf /tmp/html /var/www \
    && chmod +x /tmp/flag.sh \
    && cp -f /tmp/flag.sh /flag.sh

# CMD ["/bin/sh", "-c", "/tmp/start.sh"]
