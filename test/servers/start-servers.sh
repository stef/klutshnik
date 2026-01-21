#!/bin/sh

ORACLE=${ORACLE:-../../../server/zig-out/bin/klutshnikd}
PIDS=""

cleanup() {
 echo cleanup killing klutshnikds "${PIDS}"
 kill "${PIDS}"
 exit
}

start_server() {
   printf "starting klutshnikd %s\n" "$1"
   cd "$1" || exit 1
   if [ "$1" = "$ORACLE_STRACE"  ]; then
      strace -I1 --kill-on-exit -fo strace.log "$ORACLE" >log 2>&1 &
   else
      "$ORACLE" >log 2>&1 &
   fi
   PIDS="$PIDS $!"
   cd ..
}

start_server 0
start_server 1
start_server 2
start_server 3
start_server 4

sleep 0.3

trap "cleanup" INT TERM QUIT
if [ -n "$ORACLE_TAIL" ]; then
   tail -n 50 -f "$ORACLE_TAIL"/log
else
   while true; do sleep 1 ;done
fi
