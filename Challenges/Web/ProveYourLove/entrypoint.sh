#!/bin/sh

sed -i "s/moectf{testflag}/$FLAG/" /app/app.py

export FLAG=""
python /app/app.py
