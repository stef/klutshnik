# NAME

klutshnikd - klutshnik Key Management System (KMS) daemon

# SYNOPSIS

`klutshnikd [init]`

# DESCRIPTION

klutshnikd is the server-side component of the Klutshnik Key Management
System (KMS) protocol. It provides a secure, sharded environment for
managing cryptographic keys using a threshold architecture. In this
system, no single server ever holds a complete key; instead, a threshold
of sers must collaborate to perform cryptographic operations.

In this system, the `client` interacts with a KMS
that securely and efficiently stores secret key material, in
order to decrypt and rotate keys for data that is stored in encrypted
form on untrusted storage devices/services like a hard drive or cloud provider.

The most important aspects are:

- **Asymmetric Encryption:** Encryption only requires a public key.
- **Threshold Security:** The Key Encryption Key (KEK) is split into shares and distributed across multiple servers. No single server can compromise the key.
- **Privacy-Preserving:** Object identifiers and keys are hidden from the KM (Key Management) servers through blinding techniques.
- **Secure Transport:** All key transport to and from KM servers are secure.
- **Verifiability:** Identifying KM servers that respond with corrupt values.
- **Efficient Rotation:** Rotating the KEKs does not require downloading or re-encrypting the underlying data.
- **Zero-knowledge Updates:** Updating the KEKs can be done by untrusted storage without learning anything.

klutshnikd is based on established cryptographic research, notably
"Updatable Oblivious Key Management for Storage Systems" by Stanislaw Jarecki,
Hugo Krawczyk, and Jason Resch (https://eprint.iacr.org/2019/1275)

Detailed configuration options are documented in `klutshnikd.cfg(5)`.

# Initializiation

```sh
klutshnikd init
```

Checks if the `ltsigkey` and `noisekey` paths in the configuration point
to existing files. If not, the server generates new identity keys and
saves them.

Finally, this operation always prints out the base64-encoded long-term
public signing and noise keys so that these can be communicated to the
other KM servers and added to all the `authorized_keys` files of these servers.

The server exits after this.

# Regular Operation

The klutshnikd server runs in the foreground and emits log messages to standard output. If
you want to run it as a daemon, you should deploy it using service supervision
tools such as s6 (https://skarnet.org/software/s6/), runit (https://smarden.org/runit/) or daemontools (https://cr.yp.to/daemontools.html).

The klutshnikd server does not take any parameters on the command
line, but any settings can be overridden by environment
variables which are the all uppercase configuration variable names
prefixed with `KLUTSHNIK_`. For example, verbosity can be affected by running:

```sh
# KLUTSHNIK_VERBOSE=true klutshnikd
```

See `klutshnikd.cfg(5)` for a list of available configuration options.

# SECURITY CONSIDERATIONS

You **SHOULD** back up your configuration, especially your `LTSIGKEY`,
`NOISEKEY`, `SSL_CERT`, `SSL_KEY`, and `RECORD_SALT` settings. The database should be backed up too.

# REPORTING BUGS

https://github.com/stef/klutshnik/issues/

# AUTHOR

Written by Stefan Marsiske.

# COPYRIGHT

Copyright © 2025 Stefan Marsiske. License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it. There is NO WARRANTY, to the extent permitted by law.

# SEE ALSO

`https://klutshnik.info`

`klutshnik(1)`, `klutshnikd.cfg(5)`
