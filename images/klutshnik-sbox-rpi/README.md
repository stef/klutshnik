# Klutshnik Raspberry Pi Image builder

This directory builds a ready-to-run Klutshnik server image for Raspberry Pi. The image is based on Alpine Linux and built using [raspi-alpine/builder](https://github.com/raspi-alpine/builder).

The image is designed for minimal attack surface. Only SSH and Klutshnik run by default. The Klutshnik server is sandboxed using `bubblewrap(1)` and restricted with Seccomp BPF rules. The root filesystem is mounted read-only, with `/etc` writable via an overlay stored on `/data`. All Klutshnik data and logs live on the `/data` partition.

## Prerequisites

You need:

- Docker
- zig
- qemu-aarch64 and `binfmt` support (only if building on non-ARM64 hosts)

On Debian/Ubuntu, the `binfmt` rules come from the `qemu-user-binfmt` package.

## Building the Image

```sh
ARCH=aarch64 ./build_image.sh
```

The output lands in `./output/sdcard.img.gz`.

### Architecture Compatibility

| Board                  | armhf | armv7 | aarch64 |
| ---------------------- | :---: | :---: | :-----: |
| Pi Zero, Pi 1          |   ✓   |       |         |
| Pi 2                   |   ✓   |   ✓   |         |
| Pi 3, Pi Zero 2 W, CM3 |   ✓   |   ✓   |    ✓    |
| Pi 4, Pi 400, CM4      |       |   ✓   |    ✓    |

Currently only the aarch64 variant is tested. The other architectures may work but are not guaranteed.

The results are stored in the `./output` directory.

## Writing to SD Card

First, identify your SD card device:

```sh
lsblk
```

Look for the device matching your SD card size (for example, `/dev/sdb` or `/dev/mmcblk0`).

Then write the image:

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

**Change the password immediately after first login:**

```sh
passwd
```

For ongoing access, upload your SSH public key:

```sh
ssh-copy-id root@YOUR_PI_IP
```

Then disable password authentication by editing `/etc/ssh/sshd_config` and setting:

```
PasswordAuthentication no
```

Restart SSH:

```sh
/etc/init.d/sshd restart
```

If you prefer access only via serial console, you can disable SSH entirely:

```sh
rc-update del sshd
```

## TLS Certificates

The image generates a self-signed certificate at `/etc/klutshnik/cert.pem`. For local or VPN use, this is fine.

For public-facing servers, the image includes `acme.sh`, `acme-tiny`, and `certbot`. You need a domain name pointing to your Pi. Example with certbot:

```sh
certbot certonly --standalone --preferred-challenges http -d your-domain.example.com
```

## Adding the Device to Your Client Config

After first boot, retrieve the server's public keys:

```sh
ssh root@YOUR_PI_IP 'cat /etc/klutshnik/ltsig.key.pub'
ssh root@YOUR_PI_IP 'cat /etc/klutshnik/cert.pem'
```

Save the certificate to a file on your client machine (for example, `pi1-cert.pem`).

Add a section to your `klutshnik.cfg`:

```toml
[servers.pi1]
host = "192.168.1.100"  # Replace with the Pi's IP address
port = 443
ssl_cert = "cert.pem"      # Use the self-signed cert by default
ltsigkey = "<The Pi's Public LTSIG Key>"
```

If you are using a CA-signed certificate, omit the `ssl_cert` line.

## Setting Up authorized_keys

Each Klutshnik server needs to know the public keys of all other servers in your threshold setup. These are stored in `/etc/klutshnik/authorized_keys`.

When you add a new server to your cluster:

1. Retrieve its public key (from the first-boot output or `/etc/klutshnik/ltsig.key.pub`).
2. Add that key to the `authorized_keys` file on every other server.
3. Copy the combined `authorized_keys` file (containing all servers' keys) to the new server.

The file format is one base64-encoded public key per line.

## Tor Hidden Service

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
