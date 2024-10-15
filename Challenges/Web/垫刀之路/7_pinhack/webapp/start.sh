#!/bin/bash
sed -i "s/moectf{test}/$FLAG/g" /app/flag

export FLAG=fake_flag
FLAG=fake_flag

rm -rf /app/start.sh

python3 /app/app.py
