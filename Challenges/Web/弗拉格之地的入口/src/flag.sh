#!/bin/sh

sed -i "s/moectf{test}/$FLAG/" /var/www/html/webtutorEntry.php

export FLAG=not_flag
FLAG=not_flag
