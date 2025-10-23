#!/bin/sh

cd servers || exit 1
rm -rf ./*/data/[0-9a-f]*
ORACLE_STRACE=1 ./start-servers.sh &
SERVERS_PID=$!
cd ..
./test.sh
klutshnik delete "keyid1" <kltsk
rm -fr otherclient/keystore/[0-9a-f]* keystore/[0-9a-f]*
./test.sh
echo kill "$SERVERS_PID"
kill "$SERVERS_PID"
