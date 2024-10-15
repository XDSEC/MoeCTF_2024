#!/bin/sh
sed -i "s/moectf{test}/$FLAG/g" /tmp/flag
echo "hhhhhhhhhhhhhhhhhhhhhhhhhh"

export FLAG=not_flag
FLAG=not_flag
# rm -rf $0
rm -rf /flag.sh /tmp/flag.sh /tmp/html

