#!/bin/bash

# ping www.baidu.com
service mariadb start
sed -i "s/flag{fake_flag}/$FLAG/" /app/smbms2.sql
mariadb -uroot < /app/smbms2.sql
# echo 1111111111111111
# cat /dev/zero > /dev/null
/app/tomcat/bin/catalina.sh run
