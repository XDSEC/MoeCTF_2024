#!/bin/sh
sed -i "s/moectf{test}/$FLAG/g" /var/www/html/flag.php
echo "hhhhhhhhhhhhhhhhhhhhhhhhhh"

export FLAG=not_flag
FLAG=not_flag
