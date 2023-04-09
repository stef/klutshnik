#!/bin/sh
set -e
mkdir ../config
dd if=/dev/urandom of=../config/auth.key bs=32 count=1
echo 'pubkey="'`python klutshnik/genkey.py ../config/kms.key`'"' | tee -a ../klutshnik.cfg
cd ..
./kms 10000 config/kms.key config/auth.key
