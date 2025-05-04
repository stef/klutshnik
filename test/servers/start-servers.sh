#!/bin/sh -x

ORACLE=${ORACLE:-../../../server/zig-out/bin/klutshnikd}
PIDS=""

cleanup() {
 echo killing klutshnikds ${PIDS}
 kill ${PIDS}
 exit
}

function start_server() {
   printf "starting klutshnikd %s" "$1"
   cd "$1"
   "$ORACLE" >log 2>&1 &
   PIDS="$PIDS $!"
   sleep 0.1
   cd - >/dev/null
}

start_server 0
start_server 1
start_server 2
start_server 3
start_server 4

trap "cleanup" INT
tail -f 0/log
#while true; do sleep 1 ;done
