# Klutshnik Raspberry Pi Image builder

This directory contains all the requisites for building a ready-to-run Klutshnik server image for Raspberry Pi (RPi) 3 and 4. The image is based on Alpine Linux and built using [raspi-alpine/builder](https://github.com/raspi-alpine/builder).

The image is designed for minimal attack surface. Only SSH and Klutshnik run by default. The Klutshnik server is sandboxed using `bubblewrap(1)` and restricted with Seccomp BPF rules. The root filesystem is mounted read-only, with `/etc` writable via an overlay stored on `/data`. All Klutshnik data and logs live on the `/data` partition.

## Prerequisites

You need:

- Docker
- Zig
- qemu-aarch64 and `binfmt` support (only if building on non-ARM64 hosts)

On Debian/Ubuntu, the `binfmt` rules come from the `qemu-user-binfmt` package.

## Building the Image

```sh
ARCH=aarch64 ./build_image.sh
```

The output lands in `./output/sdcard.img.gz`.

Setting the `ARCH` variable affects which RPi versions the image will run on:

| Board                                     | armhf | armv7 | aarch64 |
| ----------------------------------------- | :---: | :---: | :-----: |
| RPi Zero                                  |  ✅   |       |         |
| RPi 1                                     |  ✅   |       |         |
| RPi 2                                     |  ✅   |  ✅   |         |
| RPi 3, RPi Zero 2 W, RPi Compute Module 3 |  ✅   |  ✅   |   ✅    |
| RPi 4, RPi 400, RPi Compute Module 4      |       |  ✅   |   ✅    |

Currently only the aarch64 variant is tested. The other architectures may work but are not guaranteed.

The results are stored in the `./output` directory.

## Writing to SD Card

To write the image:

```sh
zstd -dc output/sdcard.img.zst >sdcard.img
sudo dd if=sdcard.img of=/dev/YOUR_SD_DEVICE
```

Replace `/dev/YOUR_SD_DEVICE` with your actual device. Double-check before running, as `dd` will overwrite whatever device you specify.

## First Boot

The image initializes itself on first boot. It generates keys, self-signed TLS certificates, and a Seccomp BPF sandboxing ruleset.

You can access the device via serial console or SSH. The default credentials are:

- Username: `root`
- Password: `klutshnik`

**Change the password immediately after first login.**

Furthermore, you should either disable SSH (if you want
only serial port access), or upload your SSH key to
`/root/.ssh/authorized_keys` and disable SSH password logins.

## TLS Certificates

The image generates a self-signed certificate at `/etc/klutshnik/cert.pem`. For local or VPN use, this is fine.

For public-facing servers, the image includes `acme.sh`, `acme-tiny`, and `certbot` which you can use to get proper TLS certificates. You need a domain name pointing to your Pi. For example, with certbot:

```sh
certbot certonly --standalone --preferred-challenges http -d your-domain.example.com
```

## Configuration

Before using your new Klutshnik RPi you need to add the device to
your Klutshnik client config. The following template needs to be
completed and added to your `klutshnik.cfg` file `[servers]` section:

```toml
[servers.<devicename>]
# address of server
host="<ip address>"
port=443
# public key of the server
ssl_cert = "cert.pem"
ltsigkey="<public ltsigkey>"
```

In order:

- The ~<devicename>~ can be any unique name you want to give to your device.
- The ~host~ is the IP address of the device where this Klutshnik server will be available.
- The ~port~ is the port where this Klutshnik server will be available. By default it is 443.
- By default, ~ssl_cert~ points to ~/etc/klutshnik/cert.pem~, which is a self-signed certificate. If you are using proper official Certificate Authority issued TLS certs, you can omit this line.
- The ~ltsigkey~ is the long-term signing public key of the newly set up Klutshnik device. You can find it at ~/etc/klutshnik/ltsig.key.pub~

## Setting Up authorized_keys

Each Klutshnik server needs to know the public keys of all other servers in your threshold setup. These are stored in `/etc/klutshnik/authorized_keys`.

When you add a new server to your cluster:

1. Retrieve its public key (from the first-boot output or `/etc/klutshnik/ltsig.key.pub`).
2. Add that key to the `authorized_keys` file on every other server.
3. Copy the combined `authorized_keys` file (containing all servers' keys) to the new server.

The file format is one base64-encoded public key per line.

## (Optional) Tor Hidden Service Setup

Tor is pre-installed and configured. To enable it:

```sh
rc-update add tor default
/etc/init.d/tor start
```

The hidden service hostname is at `/var/lib/tor/klutshnik/hostname` after Tor starts.

## Backups

Back up these directories regularly, to prevent data loss and to allow for recovery in case of a server failure:

- `/etc/klutshnik` (keys, certificates, configuration)
- `/data/klutshnik` (key shares and operational data)

In a proper threshold setup, you can encrypt these backups with Klutshnik itself.
