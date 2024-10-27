#!/bin/sh

mkdir /home/ctf/dev
dd if=/dev/random of=/home/ctf/dev/random bs=8 count=1
echo $FLAG > /home/ctf/flag
export FLAG=
/etc/init.d/xinetd start
sleep infinity
