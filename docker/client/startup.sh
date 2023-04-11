#!/bin/sh
set -e
./macaroon create -a config_host/auth.key | tee godmode.key | ./macaroon dump
cat godmode.key > config_host/godmode.b64
mkdir config
cd python
./genkey.py client.tmp | tee ../config_host/authorized_keys.tmp | base64 -d >>client.tmp
base64 < client.tmp > ../config/client.key
tr -d '[:space:]' < ../config_host/authorized_keys.tmp > ../config_host/authorized_keys # Workaround, will fuck with multiple keys!
cd ..
python gen_config.py config_host/ | tee python/klutshnik.cfg
/bin/sh -i 
