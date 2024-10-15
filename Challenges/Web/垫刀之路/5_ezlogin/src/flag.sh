#!/bin/sh
sed -i "s/moectf{test}/$FLAG/g" /var/www/html/login.php
echo "hhhhhhhhhhhhhhhhhhhhhhhhhh"

mysql -uroot < /tmp/ezlogin.sql

export FLAG=not_flag
FLAG=not_flag
# rm -rf $0
rm -rf /flag.sh /tmp/flag.sh /tmp/html

