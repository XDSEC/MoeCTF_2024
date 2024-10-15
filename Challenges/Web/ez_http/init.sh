#!/bin/sh

sed -i "s/moectf{testflag}/$FLAG/" /var/www/html/index.php
export FLAG=""
php-fpm -D
nginx -g 'daemon off;'
