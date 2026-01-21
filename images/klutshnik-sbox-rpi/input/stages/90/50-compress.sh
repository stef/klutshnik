#!/bin/sh

apk add zstd
colour_echo ">> Compress images"
# copy final image
mkdir -p ${OUTPUT_PATH}
zstd --ultra -22 -c ${IMAGE_PATH}/sdcard.img >${OUTPUT_PATH}/${IMG_NAME}.img.zst
zstd --ultra -22 -c ${IMAGE_PATH}/rootfs.ext4 >${OUTPUT_PATH}/${IMG_NAME}_update.img.gz
