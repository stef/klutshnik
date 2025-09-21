#!/bin/sh -e

if [ ! -d klutshnik ]; then
   git clone https://github.com/stef/klutshnik
else
   cd klutshnik
   git pull origin master
   cd ..
fi
cd klutshnik/server
if [ "$ARCH" = "armv7" ]; then
   zig build -Doptimize=ReleaseSafe -freference-trace -Dpie=true -Drelro=true -Dsystem_libs=false -Dtarget=arm-linux
else
   if [ "$ARCH" != "aarch64" ]; then
      echo 'please set $ARCH to either armv7 or aarch64'
      exit 1
   fi
   zig build -Doptimize=ReleaseSafe -freference-trace -Dpie=true -Drelro=true -Dsystem_libs=false -Dtarget=aarch64-linux
fi
cp zig-out/bin/klutshnikd ../../input
git rev-parse --short HEAD >../../input/klutshnik-rev
cd ../../

docker run --rm -it -v "$PWD"/input:/input -v "$PWD"/output:/output -e ARCH --env-file build.env ghcr.io/raspi-alpine/builder
