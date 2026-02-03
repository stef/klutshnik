# NAME

klutshnik - command-line client for an updatable threshold KMS system

# SYNOPSIS

     klutshnik init <configfile>

     klutshnik create  <keyname> [<ltsigkey>] <pk>

     klutshnik encrypt <pk> <plaintext> <ciphertext>

     klutshnik decrypt [<ltsigkey>] <ciphertext> <plaintext>

     klutshnik rotate  <keyname> [<ltsigkey>] <pk-and-delta>

     klutshnik refresh <keyname> [<ltsigkey>] <pk>

     klutshnik delete  <keyname> [<ltsigkey>]

     klutshnik update  <delta>  <files2update>

     klutshnik adduser <keyname> <b64_pubkey> <permissions> [<ltsigkey>]

     klutshnik deluser <keyname> <b64_pubkey> [<ltsigkey>]

     klutshnik listusers <keyname> [<ltsigkey>]

     klutshnik import <keyid> <config_token> [<ltsigkey>]

     klutshnik provision <port> <config> <auth_keys> <type> [<ltsigkey>]

# DESCRIPTION

klutshnik is a CLI client for an updatable threshold Key Management
System (KMS) protocol. In this system, the client interacts with a group
of KM (Key Management) servers to derive cryptographic keys without any single entity
ever possessing the full secret. This architecture is designed to
protect data stored on untrusted storage services.

The most important aspects are:

- **Asymmetric Encryption:** Encryption only requires a public key.
- **Threshold Security:** The Key Encryption Key (KEK) is split into shares and distributed across multiple servers. No single server can compromise the key.
- **Privacy-Preserving:** Object identifiers and keys are hidden from the KM servers through blinding techniques.
- **Secure Transport:** All key transport to and from KM servers are secure.
- **Verifiability:** Identifying KM servers that respond with corrupt values.
- **Efficient Rotation:** Rotating the KEKs does not require downloading or re-encrypting the underlying data.
- **Zero-knowledge Updates:** Updating the KEKs can be done by untrusted storage without learning anything.

klutshnik is based on established cryptographic research, notably "Updatable
Oblivious Key Management for Storage Systems" by Stanislaw Jarecki,
Hugo Krawczyk, and Jason Resch (https://eprint.iacr.org/2019/1275)

## Configuration

For information on configuring Klutshnik, see the man page
`klutshnik.cfg(5)`.

## Command-line Usage

### Long-term signing key (ltsigkey)

Klutshnik uses EdDSA long-term signing keys for authentication towards
the key management servers. This key can be stored on disk and referenced in the `klutshnik.cfg(5)` config file.
Alternatively, Klutshnik can
take the client long-term signing key on the standard input.

Note: When decrypting a file, the long-term signing key (if provided on
stdin) must be concatenated with the ciphertext. It is recommended to use pwdsphinx
(https://github.com/stef/pwdsphinx) as a "storage" for the client's
long-term signing keys, since it handles keys also in a threshold
setup in a most secure manner.

### Key Names

Key IDs are arbitrary strings used to identify your records.
Internally, these names are hashed using the `id_salt` from the
configurations `[client]` section into a unique key identifier.
Given that this `id_salt` is necessary for accessing your records,
it is strongly recommended to use a unique salt and maintain a secure backup of
this value. If you use a commonly-used `id_salt` (such as the default
salt), it is likely that people can guess your record ids.

## Operations

### Initialize a new config

```sh
klutshnik init <configfile>
```

Initializes a new configuration. If a master key does not exist at the
configured `clientkey_path` (see `klutshnik.cfg(5)`), a new one is generated and saved at the pointed location. It prints your long-term signing and short-term signing public keys to standard output. This long-term public key value must be manually added to the `authorized_keys` files of any Klutshnik server that you want to use.

Furthermore, the `init` operation also checks if the directory pointed at by the
`keystore` value in the `[client]` section exists and if not creates this.

It is recommended that you store your client master key in a more
secure location than your disk, such as a password
manager like `pwdsphinx(1)`. See `klutshnik.cfg(5)` for more details.

### Create a new key

```sh
klutshnik create <keyname> [<ltsigkey>]
```

Creates a new key identified by `<keyname>`. `ltsigkey` is the long-term signing private key as described above, and should be provided if the `ltsigkey_path` config option is not set.

This operation outputs the public key, which can
be used to encrypt files. The encrypted files can be decrypted
using the private key associated with the key name.

It also sets the long-term signing public key of the creator as
the owner of the key, giving them all permissions.

### Encrypt a file

```sh
klutshnik encrypt <public_key> <plaintext >ciphertext
```

Encrypts data using the provided public key. This is a purely local
operation and does not require a long-term signing key or network
connectivity to the KM servers. Users who have no
authorization to interact with the key on the KMS must rely on
an authorized user to provide the public key of the current
epoch.

### Decrypt a file

```sh
klutshnik decrypt [<ltsigkey>] <ciphertext >plaintext
```

Decrypts the input ciphertext and outputs the plaintext.
This requires connectivity to a threshold of key management servers.
If your long-term signing key is not in the configuration,
it must be prefixed to the ciphertext on standard input.

### Rotate a key

```sh
klutshnik rotate <keyname> [<ltsigkey>] >pubkey-and-delta
```

Generates a new epoch for the specified key.
If your long-term signing key is not in the configuration (see klutshnik.cfg(5)),
it must be provided on standard input.
The output of this operation is:

- the new public key, which you should distribute to anyone who is
  expected to encrypt to this key, and
- your delta update token which is required to update the encryption
  of the files encrypted with this key

**NOTE**: Run the `klutshnik update` operation on
all files encrypted with the rotated key by applying this delta update token to them.

**SECURITY WARNING:** The delta update token must be kept secret. If
leaked, an adversary could potentially neutralize the forward secrecy
and post-compromise security properties of this protocol for the current
and the previous key.

### Update a file with a rotated key

```sh
klutshnik update <delta> <files2update>
```

Applies an delta update token (generated from the `klutshnik rotate`
operation) to a list of files. This operation does not
require a long-term signing key. It can be done offline, without
connectivity to the key management servers.
In fact, this operation can run on the storage server itself.

**SECURITY WARNING:** The delta update token must be kept secret. If
leaked, an adversary could potentially neutralize the forward secrecy
and post-compromise security properties of this protocol for the current
and the previous key.

### Refresh local key metadata

```sh
klutshnik refresh <keyname> [<ltsigkey>] >pk
```

Updates the client's local cache with the latest metadata.
The following metadata are refreshed, and each clients should run this operation to refresh their local copy of:

- the public key
- the current epoch
- the threshold
- the owner public key
- the shares that can be combined into the public key

This operation outputs the current public key associated with the
`keyname`.

### Delete a key

```sh
klutshnik delete <keyname> [<ltsigkey>]
```

Deletes the shares of the specified key from all key management servers.
If your ltsigkey is not in the configuration,
it must be provided on standard input.

### Authorize a user

```sh
klutshnik adduser <keyname> <b64 pubkey> <owner,decrypt,update,delete> [<ltsigkey]
```

Grants permissions to another user. The parameters to this operation are:

- the `keyname` to which a new user is added,
- the base64-encoded long-term public signing-key,
- a comma-separated list of permissions: owner,decrypt,update,delete

The output of this operation is the base64-encoded serialized setup
related to this key. This data is the `keyid`, and the `[server]`
section with `ltsigkey` and `ssl_cert` files inlined. This "token"
must be passed to the user who has been authorized, so they can
`klutshnik import` this into their own configuration

### Delete a user

```sh
klutshnik deluser <keyname> <b64_pubkey> [<ltsigkey>]
```

Revokes all permissions for a user specified by their public key.
This operation can only be done by a user with `owner` permissions
associated to their `ltsigkey`.

### List authorizations of users

```sh
klutshnik listusers <keyname> [<ltsigkey>]
```

Lists all authorized users and their associated permissions for a
specific key. This operation can only be done by a user with `owner` permissions
associated to their `ltsigkey`.

### Import Foreign Key Setup

```sh
klutshnik import <keyid> <KLTCFG-...b64...> [<ltsigkey]
```

Imports a shared key setup provided by another user.
Non-owner users who have been authorized must import
the setup of the owner into their local `keystore`,
unless they have the same `id_salt` value and the same `[server]` section in their config as the owner.
This operation automatically runs a `refresh` to synchronize
the local state.

### Provisioning Klutshnik Microcontroller Devices

```sh
klutshnik provision <serial port> <klutshnik.cfg> <authorized_keys> <uart|esp> [<ltsigkey]
```

Provisions a microcontroller-based Klutshnik server.
It is possible to run Klutshnik servers on microcontrollers like ESP32, or
Cortex-M series ARM devices (see https://github.com/stef/klutshnik-zephyr).
After installing the firmware on a microcontroller, it needs to be configured like a regular server.

The parameters to this operation are:

- `serial port`: the first (some devices have two) serial port when connected
  via USB associated with the device. A common value is `/dev/ttyACM0`
- `klutshnik.cfg`: the client config file which will be consulted and updated
  during the provisioning.
- `authorized_keys`: a file containing the authorized keys of all the other
  Klutshnik servers in the client setup. If they are not all available,
  they can be added later using the USB serial shell of the device, as specified
  in the firmware's documentation
- `uart|esp`: depending on whether the Klutshnik device is communicating the
  Klutshnik protocol over the 2nd USB serial port or is an ESP32 device
- `ltsigkey`: the long-term signing key to be used for authentication.

**WARNING**: If you add a new USB serial-based Klutshnik device, make sure that the
existing config has no `servers` subsection with the name `usb-cdc0` as that
will be overwritten during the provisioning. If this happens anyway, a backup
of the original config file is made.

If this operation works, the device gets the `authorized_keys` file and the
owner's client long-term signing and Noise public keys. A new `servers` sub-section, having either the Bluetooth MAC or `usb-cdc0` as a name, is added to `klutshnik.cfg`, the client config file.

After this operation is completed, a base64 encoded `authorized_keys` entry is presented, which **MUST** be added to all `authorized_keys` files of all the other Klutshnik servers specified in the client config.

# SECURITY CONSIDERATIONS

- You **MUST** keep delta update tokens private! Leaking them compromises the system’s forward secrecy and post-compromise security.
- It is **RECOMMENDED** to store your master signing key
  in a dedicated secure storage or password manager rather than plain
  files on disk. `pwdsphinx` (https://sphinx.pm) provides native support for this.
- Do not let any 3rd-party hold enough shares to achieve the threshold
- You **SHOULD** back up your configuration, especially the `id_salt`
  and the names of the servers you are using. Losing them means losing
  access to your data.

# REPORTING BUGS

https://github.com/stef/klutshnik/issues/

# AUTHOR

Written by Stefan Marsiske.

# COPYRIGHT

Copyright © 2025 Stefan Marsiske. License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it. There is NO WARRANTY, to the extent permitted by law.

# SEE ALSO

`https://klutshnik.info`

`klutshnik.cfg(5)`

`https://sphinx.pm`
