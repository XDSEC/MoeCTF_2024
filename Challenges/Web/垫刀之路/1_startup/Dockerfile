FROM ctftraining/base_image_nginx_php_73

COPY src /tmp

RUN cp -rf /tmp/html /var/www \
    && chmod +x /tmp/flag.sh \
    && cp -f /tmp/flag.sh /flag.sh \
    && cp -f /tmp/flag /flag

# CMD ["/bin/sh", "-c", "/tmp/start.sh"]
