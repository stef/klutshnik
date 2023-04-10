#!/bin/sh
set -e
./macaroon create -a config_host/auth.key | tee godmode.key | ./macaroon dump
cat godmode.key | base64 -w0 > config_host/godmode.b64
mkdir config
cd python
./genkey.py client.tmp | base64 -d >>client.tmp
base64 < client.tmp > ../config/client.key
cd ..
python gen_config.py config_host/ | tee python/klutshnik.cfg
/bin/sh -i 
