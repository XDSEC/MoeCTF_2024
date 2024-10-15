#!/bin/sh

echo "$FLAG" >> /etc/passwd
export FLAG=""
php-fpm -D
nginx -g 'daemon off;'
