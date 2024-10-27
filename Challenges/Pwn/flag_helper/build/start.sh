#!/bin/sh

echo $FLAG > /flag
echo $FLAG > /flag.txt
chown root:ctf /flag
chown root:ctf /flag.txt
export FLAG=
/etc/init.d/xinetd start
sleep infinity
