# NAME

klutshnik.cfg - configuration for for klutshnik client `klutshnik`

# DESCRIPTION

This man page describes the format and various ways of configuring the
`klutshnik` CLI client.

The client looks for the configuration in the following files and order:

  - /etc/klutshnik/config
  - ~/.config/klutshnik/config
  - ~/.klutshnikrc
  - ./klutshnik.cfg

The configuration file format is TOML, see https://toml.io/ .

## `[Client]` SECTION

This section configures the general options of the client.

### `ID_SALT`

This value is used as an input to generating keyids for your records.
You must set/change this value, it ensures that your record ids are
unique. You must also make sure to not lose this value, if you do, you
lose access to your records. Has no default, must be set.

### THRESHOLD

This value sets the threshold for your server configuration. This
value is tightly dependent on the number of servers you have
configured in the `[servers]` section.

In order to be able to rotate your DEK keys you need to have at least
`(t-1)*2 + 1` servers configured in your `[servers]` section.  That
means for the smallest threshold setup, this value is 2 and you need
three servers configured in the `[servers]` section. The upper limit
of this value 63, but it is highly optimistic to run such large setups
reliably.

### `TS_EPSILON`

The time in seconds a distributed keygen (DKG) protocol message is
considered fresh. anything older than this is considered invalid and
aborts a DKG. Higher values help with laggy links, lower values can
be fine if you have high-speed connections to all servers. Default: 1200s

### CLIENTKEY_PATH

This variable is a path pointing at a file containing a secret
master key of the client. If this value is not set, it is
expected on standard input for all operations that require this key.

Leaving this value commented out allows to pipe in the private key
from password managers, or other more secure storage than the
filesystem.

If this path is set, but the file does not exist `klutshnik init` will
initialize this file.

### LTSIGPUB

This variable must be set to the public long-term signing key of the
client, this public key must be base64 encoded and this encoded value
prefixed by the string "KLTPK-". The operation `klutshnik init`
initialized this value.

### DEBUG

This is a boolean variable which enables a lot of low-level debug
information.

### VERBOSE

This is a boolean variable which makes the client more verbose.

### KEYSTORE

This variable holds a path where the public key, their shares and
threshold setup information for each of your keys is stored.

### `[servers]` SECTION

This section contains the list of servers for the client. The number
of items in this list needs one more entry than the value of
`threshold`, but in order to benefit from key updates, the number of
servers must be `(t-1)*2 +1`, where `t` is the `threshold` value
configured in the `[client]` section.

Servers are in their own sections, with the following pattern:
`[servers.<name>]` Where name should be unique among all servers,
simple labels like kms1, kms2, etc. are totally fine.

#### ADDRESS

This can be either an IPv4 or IPv6 address to listen on.

#### PORT

The port the server listens on.

#### `SSL_CERT`

This variable is a path pointing at a file containing a TLS
certificate. This is only needed for TLS certificates that are
self-signed or otherwise not in signed by CAs in your CA store.

#### LTSIGKEY

This variable is a path pointing at a file containing a public
long-term signing key of the server. You need to get this from the
operators of the klutshnik server.

#### NOISEKEY

This variable is a path pointing at a file containing a public
long-term Noise key of the server. You need to get this from the
operators of the klutshnik server.

# FILES

  - /etc/klutshnik/config
  - ~/.config/klutshnik/config
  - ~/.klutshnikrc
  - ./klutshnik.cfg

# SECURITY CONSIDERATIONS

You **SHOULD** back up your configuration file, most importantly the
value of `id_salt` and your ltsigkey.

# REPORTING BUGS

https://github.com/stef/klutshnik/issues/

# AUTHOR

Written by Stefan Marsiske.

# COPYRIGHT

Copyright © 2025 Stefan Marsiske.  License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.  There is NO WARRANTY, to the extent permitted by law.

# SEE ALSO

`https://klutshnik.info`

`klutshnik(1)`
