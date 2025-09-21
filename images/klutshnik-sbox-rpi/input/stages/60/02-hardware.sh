#!/bin/sh

echo 'cdc_ether' >"$ROOTFS_PATH"/etc/modules-load.d/cdc_ether.conf
echo "cdc_ether" >>"$ROOTFS_PATH"/etc/modules

sed "/ttyAMA0/ittyAMA0         root:dialout 0660" -i "$ROOTFS_PATH"/etc/mdev.conf
# enable hardware serial console
echo 'dtoverlay=disable-bt' >>"$BOOTFS_PATH"/config.txt
#echo 'dtoverlay=miniuart-bt' >>"$BOOTFS_PATH"/config.txt
echo 'enable_uart=1' >>"$BOOTFS_PATH"/config.txt

# start a login terminal on the serial port
sed -e "s/#ttyS0/ttyAMA0/" -e "s/ttyS0/ttyAMA0/" -i "$ROOTFS_PATH"/etc/inittab
