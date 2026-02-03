# NAME

klutshnik.cfg - configuration for the Klutshnik client `klutshnik`

# DESCRIPTION

This man page describes the format and various ways of configuring the
`klutshnik` CLI client.

The client looks for configuration files in the following order:

- `/etc/klutshnik/config`
- `~/.config/klutshnik/config`
- `~/.klutshnikrc`
- `./klutshnik.cfg`

The configuration file format is TOML.

## `[Client]` SECTION

This section configures general client behavior.

### `ID_SALT`

A unique salt used to generate all key IDs for your records.
It has no defaults, and you must set this value.
It ensures that your record ids are
unique. If you lose this value, you will lose access to all your keys.

### THRESHOLD

This value sets the threshold (t) for your server configuration. This
value is tightly dependent on the number of servers you have
configured in the `[servers]` section.

In order to be able to rotate your data encryption key (DEK), you need to have at least
`(t-1)*2 + 1` servers configured in your `[servers]` section. That
means for the smallest threshold setup, this value is 2 and you need
three servers configured in the `[servers]` section. The upper limit
of this value 63, but it is highly optimistic to run such large setups
reliably.

### `TS_EPSILON`

The time in seconds that a Distributed Key Generation (DKG) message
is considered valid. Messages older than this are rejected to prevent
replay attacks and ensure protocol freshness.
Higher values help with laggy links, lower values can
be fine if you have high-speed connections to all servers.
Default: 1200s.

### CLIENTKEY_PATH

The path to the file containing the client's master secret key. If not set,
the key is expected on standard input for all operations that require this key.
Leaving this value unset allows piping in the private key
from password managers, or other more secure storage than the
filesystem.

If the path is set but the file does not exist, `klutshnik init` will
generate a new key and save it here.

### LTSIGPUB

The base64-encoded long-term signing public key of the client, prefixed
with `KLTPK-`. This is initialized by `klutshnik init`.

### DEBUG

This is a boolean variable which enables a lot of low-level debug
information. Default: false.

### VERBOSE

This is a boolean variable which increases the detail of progress
messages. Default: false.

### KEYSTORE

The path to the directory where public keys, shares, and threshold metadata
are stored locally.

## `[servers]` SECTION

This section contains the list of servers for the client. The number
of items in this list needs to be at least
`threshold+1`. To benefit from key updates, the number of
servers must be `(threshold-1)*2 +1`. Here, `threshold` is the value
of the `threshold` variable in the `[client]` section.

Servers are defined in individual subsections: `[servers.<name>]`, where
`<name>` is a unique label (e.g., `kms1`, `kms2`).

### ADDRESS

The network address (IPv4, IPv6, or hostname) to listen on.

### PORT

The port number the server is listening on.

### `SSL_CERT`

The path to the server's TLS certificate. This is only needed for self-signed
certificates or those not signed by a Certificate Authority (CA) that your system's CA store trusts.

### LTSIGKEY

The path to the server's public long-term signing key. You need to get this from the klutshnik server's operator. If you are running your
own server, see `klutshnikd(8)` for how to obtain this value.

### NOISEKEY

The path to the server's public long-term Noise key, used for secure
authenticated communication. You need to get this from the klutshnik server's operator. If you are running your
own server, see `klutshnikd(8)` for how to obtain this value.

# SECURITY CONSIDERATIONS

You **SHOULD** back up your configuration file, especially the `id_salt` and
`ltsigkey`. Loss of these values will result in permanent loss of access
to your keys.

# REPORTING BUGS

https://github.com/stef/klutshnik/issues/

# AUTHOR

Written by Stefan Marsiske.

# COPYRIGHT

Copyright © 2025 Stefan Marsiske. License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it. There is NO WARRANTY, to the extent permitted by law.

# SEE ALSO

https://klutshnik.info

`klutshnik(1)`, `klutshnikd(8)`
