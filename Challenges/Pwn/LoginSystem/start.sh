#!/bin/sh
# Add your startup script
echo $FLAG > /home/ctf/flag && export FLAG=""

head -c8 /dev/urandom > /home/ctf/dev/urandom

# DO NOT DELETE
/etc/init.d/xinetd start;
sleep infinity;
