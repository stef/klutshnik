#!/bin/sh
set -e
mkdir ../config
#dd if=/dev/urandom of=../config/auth.key bs=32 count=1
echo 'pubkey="'`python klutshnik/genkey.py ../config_host/${KMS_NAME}.key`'"' | tee ../config_host/${KMS_NAME}.pub
ifconfig eth0 
cd ..
./kms 10000 config_host/${KMS_NAME}.key config_host/auth.key
