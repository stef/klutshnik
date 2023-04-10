#!/bin/sh
set -e
mkdir ../config
#dd if=/dev/urandom of=../config/auth.key bs=32 count=1
echo `python klutshnik/genkey.py ../config_host/${KMS_NAME}.key` | tee ../config_host/${KMS_NAME}.pub
ifconfig eth0 | egrep -o 'inet addr:([0-9\.]+)'  | cut -d ':' -f 2 | tee ../config_host/${KMS_NAME}.ip
cd ..
./kms 10000 config_host/${KMS_NAME}.key config_host/auth.key
