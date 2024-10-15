FROM ctftraining/base_image_nginx_mysql_php_73

COPY src /tmp

RUN cp -rf /tmp/html /var/www \
    && chmod +x /tmp/flag.sh \
    && mv -f /tmp/flag.sh /flag.sh \
    # && mv -f /tmp/fake_flag /flag

# CMD ["/bin/sh", "-c", "/tmp/start.sh"]
