#!/bin/bash

sed -i "s/moectf{testflag}/$FLAG/" /var/www/html/admin/login.php

export FLAG=""

rm -f /docker-entrypoint.sh

mysqld_safe &

mysql_ready() {
	mysqladmin ping --socket=/run/mysqld/mysqld.sock --user=root --password=root > /dev/null 2>&1
}

while !(mysql_ready)
do
	echo "waiting for mysql ..."
	sleep 3
done

php-fpm & nginx &

echo "Running..."

tail -F /var/log/nginx/access.log /var/log/nginx/error.log