#!/bin/sh

echo $FLAG > /home/ctf/flag
echo "flag{Good_old_days}" > /home/ctf/fake_flag
export FLAG=
/etc/init.d/xinetd start
sleep infinity
