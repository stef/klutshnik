# Klutshnik Raspberry PI image builder

This directory contains all the requisites for building an image that
can be written to an SD card and run on a Raspberry Pi 3+. The image
is built using
[raspi-builder](https://github.com/raspi-alpine/builder), and is based
on Alpine Linux.

The image has by default a minimal attack surface, only ssh and
klutshnik are running. The klutshnik server is sand-boxed using
`bubblewrap(1)` and restricted using Seccomp BPF rules. The image
itself is mounted read-only, with `/etc` writable using an overlay
stored on the writable partition mounted at `/data`. This `/data`
partition also contains all the data and logs of the klutshnik server.

## Building and Writing

To build the images you need to have docker, zig - and if you are not
on an aarch64 system - also qemu-aarch64 installed, and `binfmt` rules
installed which allow to run aarch64 binaries on your architecture. On
debian systems the qemu binfmt rules are provided by the
`qemu-user-binfmt` package.

You can then build the image using:

```sh
 ARCH=aarch64 ./build_image.sh
```

Setting the ARCH variable effects which pi versions the image will run on:

| Board           | armhf | armv7 | aarch64 |
|-----------------|:-----:|:-----:|:-------:|
| pi0             | ✅    |       |         |
| pi1             | ✅    |       |         |
| pi2             | ✅    | ✅    |         |
| pi3, pi0w2, cm3 | ✅    | ✅    | ✅      |
| pi4, pi400, cm4 |       | ✅    | ✅      |

currently only the `aarch64` variant is tested, the others might or
might not work.

The results are stored in the `./output` directory.

Writing the image can be done as follows:

```sh
zstd -dc output/sdcard.img.zst >sdcard.img
sudo dd if=sdcard.img of=/dev/mmcblk0
```

## First Boot

The image self-initializes at the first boot, this means it generates
keys, self-signed certificates and a Seccomp BPF sandboxing ruleset.

You can either connect via a serial port, or ssh into the raspi using
root and `klutshnik` password, which you should change
immediately. Furthermore You should either disable ssh (if you want
only serial port access), or upload your ssh key to
`/root/.ssh/authorized_keys` and disable ssh passwords logins.

In case you prefer proper TLS certificates the image has `acme.sh`,
`acme-tiny` and `certbot` pre-installed.

## Configuration

### Client Setup

Before using your new klutshnik raspi you need to add the device to
your klutshnik client config. The following template needs to be
completed and added to your `klutshnik.cfg` file `[servers]` section:

```
[servers.<devicename>]
# address of server
host="<ip address>"
port=443
# public key of the server
ssl_cert = "cert.pem"
ltsigkey="<public ltsigkey>"
```

In order:

  1. choose a device name, this might be a host name, or any other
     identifier you prefer.
  2. the ip address of your device where this klutshnik server will be
     available.
  3. Unless you are using proper official Certificate Authority issued
     TLS certs (if you do, omit the `ssl_cert` line), a file
     containing the self-signed SSL certificate.
  4. The long-term signing public key (ltsigkey) of the newly set up
     klutshnik device.

Both the self-signed SSL cert and the ltsigkey are presented to you
when you login to the device via the serial console or ssh. You can
also find the certificate in `/etc/klutshnik/cert.pem`, and the
ltsigkey at `/etc/klutshnik/ltsig.key.pub`.

### authorized_keys Setup

In order to use the new device in a threshold setup with other
klutshnik servers, the authorization key must be added to all other
klutshnik servers `authorized_keys` files and the same file must also
be installed at the new klutshnik raspi device, which is stored at
`/etc/klutshnik/authorized_keys`.

### Tor Hidden Service Setup

The image comes pre-installed with tor, and freshly configured at
first boot. If you want to enable it, you must login as root, and run:

```sh
rc-update add tor default
```

If you want to start it immediately you should also run:

```sh
/etc/init.d/tor start
```

## Backups

It is very much recommended to run regular backups of `/etc/klutshnik`
and `/data/klutshnik` to prevent any kind of data loss, in a proper
threshold setup this back-up can even be encrypted with klutshnik
itself.
