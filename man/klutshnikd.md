# NAME

klutshnikd - Klutshnik KMS server

# SYNOPSIS

`klutshnikd [init]`

# DESCRIPTION

klutshnikd is a server for an updatable threshold Key Managment Server
(KMS) protocol. In this system the `client` interacts with a `KMS`
- which stores securely and efficiently secret key material -, in
order to decrypt and rotate keys for data that is stored in encrypted
form on untrusted `storage services`.

The most important aspects are:

  - encryption only requires a public key,
  - operates in a threshold setup, splitting up the key-encryption-key
    (KEK) in a way that never manifests as such anywhere,
  - hides keys and object identifiers from the KMS,
  - offers unconditional security for key transport to/from KMS,
  - provides key-verifiability, identifying KMS' which respond with
    corrupt values,
  - provides very efficient key-rotation of the KEKs, which does not
    require re-encryption of the encrypted data itself.
  - updating the KEKs can be done even by the untrusted storage, it
    will not learn anything.

Klutshnik is based on https://eprint.iacr.org/2019/1275 "Updatable
Oblivious Key Management for Storage Systems" by Stanislaw Jarecki,
Hugo Krawczyk, and Jason Resch

The server runs in the foreground and emits log messages to standard output. If
you want to run it as a daemon, you should deploy it using service supervision
tools such as s6, runit or daemontools.

See `klutshnikd.cfg(5)` man-page for configuration details.

# Initializiation

```sh
# klutshnikd init
```

This operation checks if the `ltsigkey` and `noisekey` variables in
your configuration are pointing at non-existing files. If this is the
case, then the server generates a key and saves it at the pointed
location and prints the public key on standard output.

Finally this operation always prints out the base64 encoded long-term
public signing and noise keys so that these can be communicated to the
other KMS' and added to all the `authorized_keys` files of these.

The server exits after this.

# Regular Operation

The klutshnikd server does not take any parameters on the command
line, but any configuration settings can be overridden by environment
variables which are the all-upper-case configuration variable names
prefixed with `KLUTSHNIK_`, e.g. verbosity can be affected by running:

```sh
# KLUTSHNIK_VERBOSE=true klutshnikd
```

# SECURITY CONSIDERATIONS

You **SHOULD** back up your SSL key, `record_salt` configuration
value, long-term signing key, Noise key and of course the database
must be regularly backed up.

# REPORTING BUGS

https://github.com/stef/klutshnik/issues/

# AUTHOR

Written by Stefan Marsiske.

# COPYRIGHT

Copyright © 2025 Stefan Marsiske.  License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.  There is NO WARRANTY, to the extent permitted by law.

# SEE ALSO

`https://klutshnik.info`

`klutshnik(1)`, `klutshnikd.cfg(5)`
