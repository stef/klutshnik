#!/bin/sh

chroot_exec adduser -D -g "klutshnik daemon" -h "/data/klutshnik" "klutshnik" "klutshnik"

cp "$INPUT_PATH/klutshnikd"  "$ROOTFS_PATH/usr/bin/klutshnikd"
cp "$INPUT_PATH/init.sh" "$ROOTFS_PATH/etc/init.d/klutshnik"

mkdir "$ROOTFS_PATH/etc/klutshnik"
cp "$INPUT_PATH/klutshnik.cfg_template" "$ROOTFS_PATH/data/klutshnik/klutshnik.cfg_template"
cp "$INPUT_PATH/setup_init.sh" "$ROOTFS_PATH/etc/init.d/klutshnik-setup"
cp "$INPUT_PATH/setup.sh" "$ROOTFS_PATH/usr/bin/klutshnik-setup"
cp "$INPUT_PATH/klutshnik-rev" "$ROOTFS_PATH/data/klutshnik/klutshnik-rev"
cp "$INPUT_PATH/sbox.sh" "$ROOTFS_PATH/usr/bin/sbox.sh"
cp -a "$INPUT_PATH/test" "$ROOTFS_PATH/data/klutshnik/test"

chroot_exec rc-update add klutshnik default
chroot_exec rc-update add klutshnik-setup default
chroot_exec apk add openssl acme.sh acme-tiny certbot libsodium strace git make netcat-openbsd linux-headers g++ gcc libsodium-dev py3-virtualenv py3-pip python3-dev openssl-dev bubblewrap nginx iptables tor

chroot_exec virtualenv --system-site-packages /data/klutshnik/env

ab_git -r https://github.com/stef/liboprf/ -p "$ROOTFS_PATH/data/klutshnik/liboprf"
chroot_exec make PREFIX=/usr -C /data/klutshnik/liboprf/src install
chroot_exec /data/klutshnik/env/bin/pip install /data/klutshnik/liboprf/python
rm -rf "$ROOTFS_PATH/data/klutshnik/liboprf"

ab_git -r https://github.com/stef/klutshnik -p "$ROOTFS_PATH/data/klutshnik/klutshnik"
chroot_exec /data/klutshnik/env/bin/pip install /data/klutshnik/klutshnik/python
chroot_exec make PREFIX=/usr -C /data/klutshnik/klutshnik install
rm -rf "$ROOTFS_PATH/data/klutshnik/klutshnik"

ab_git -r https://android.googlesource.com/platform/external/minijail/ -p "$ROOTFS_PATH/data/klutshnik/minijail"
chroot_exec make OUT=/data/klutshnik/minijail -C /data/klutshnik/minijail constants.json
mv "$ROOTFS_PATH/data/klutshnik/minijail/constants.json" "$ROOTFS_PATH/data/klutshnik/"

chroot_exec apk del git netcat-openbsd linux-headers g++ gcc libsodium-dev py3-virtualenv py3-pip python3-dev openssl-dev make
chroot_exec apk add gcompat

cp -a "$ROOTFS_PATH/data/klutshnik" "$DATAFS_PATH"/
rm -rf "$ROOTFS_PATH/data/klutshnik"

