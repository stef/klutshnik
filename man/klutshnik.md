# NAME

klutshnik - command-line client for an updatable threshold KMS system

# SYNOPSIS

     klutshnik init

     klutshnik create  <keyname> [<ltsigkey] >pk

     klutshnik encrypt <pk> <plaintext >ciphertext

     klutshnik decrypt [<ltsigkey] <ciphertext >plaintext

     klutshnik rotate  <keyname> [<ltsigkey] >pk-and-delta

     klutshnik refresh <keyname> [<ltsigkey] >pk

     klutshnik delete  <keyname> [<ltsigkey]

     klutshnik update  <delta  <files2update

     klutshnik adduser <keyname> <b64 pubkey> <owner,decrypt,update,delete> [<ltsigkey]

     klutshnik deluser <keyname> <b64 pubkey> [<ltsigkey]

     klutshnik listusers <keyname> [<ltsigkey]

     klutshnik import <keyid> <KLTCFG-...> [<ltsigkey]

# DESCRIPTION

klutshnik is a CLI client for an updatable threshold Key Managment
Server (KMS) protocol. In this system the `client` interacts with a `KMS`
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

## Configuration

For information on configuring `klutshnik`, see the man-page
`klutshnik.cfg(5)`.

## Command-line usage and examples

### Long-term signing key

`klutshnik` uses EdDSA long-term signing keys for authentication
towards the KMS servers. This key can be stored on disk and referenced
in the `klutshnik.cfg(5)` config file. Alternatively `klutshnik` can
take the client long-term signing key on the standard input. Note: If
you are decrypting a file, the file itself is also expected on the
standard input. In this case the ltsigkey and the file - if required -
should be simply (in this order) concatenated.

It is warmly recommended to use pwdsphinx
https://github.com/stef/pwdsphinx as a "storage" for the client
long-term signing keys, since it handles keys also in a threshold
setup in a most secure manner.

### Key Names

KeyIds are the identifiers that you use to address your records, they
can be any kind of string. Internally this name is hashed using the
`id_salt` from the configurations `[client]` section into a unique key
identifier. As this salt is necessary to access your records, it is
strongly recommended to set the `id_salt` to some random value and to
back up this value. If you use a commonly used salt (i.e. the default
salt) chances are high that there are collisions for record ids, and
that people can guess your record ids.

## Command-line Operations

### Initialize a new config

```sh
% klutshnik init
```

This checks if the `ltsigkey_path` variable is pointing at a non-existing
file. If this is the case, then the client generates a new long-term
signing-key, saves it at the pointed location and prints the public
key on standard output. This public key value must be manually added
to the config file setting the value for `ltsigpub` in the `[client]`
section.

Furthermore this also checks if the directory pointed at by the
`keystore` value in the `[client]` section exists and if not creates
this.

Note it is recommended to store your private `ltsigkey` in a more
secure location than your disk, if possible store it in a password
manager, like `pwdsphinx(1)`, see `klutshnik.cfg(5)` for more details.

### Create a new key

Creating a new key is as simple as providing a key name and if
`ltsigkey_path` is not configured the long-term signing private key on the
standard input.

```sh
% klutshnik create <keyname> [<ltsigkey]
```

If everything went fine, the client outputs the public key, which can
be used to encrypt files. These can be decrypted by the key referenced
by the key name you provided.

This operation sets the long-term signing public key of the creator as
the owner of the key, giving all permissions to them.

### Encrypt a file

Encrypting a file requires the latest public key as provided by the
`create`, `rotate` and `refresh` operations. Users who have no
authorization to interact with the keyid on the KMS' must rely on any
of the authorized users to provide the public key of the current
epoch. This operation does not require a long-term signing key.

```sh
% klutshnik encrypt <public key> <plaintext >ciphertext
```

### Decrypt a file

Decrypting a file just pipe the ciphertext into the process and get
the plaintext on standard output. If you don't have your long-term
signing key in your configuration, this is expected as a prefix to the
encrypted file. Of course this works on the condition that enough KMS'
are responding correctly and that the file has been updated with the
delta of the current epoch.

```sh
% klutshnik decrypt [<ltsigkey] <ciphertext >plaintext
```

### Rotate a key

Rotating a key can be done by specifying the name of the key that you
want to rotate. Depending on your configuration, you must supply your
long-term signing key on standard input. The output of this operation
is:
 - the new public key, which you should distribute to anyone who is
   expected to encrypt to this key, and
 - your update delta token which is required to update the encryption
   of the files encrypted with this key.

It is essential to run the `update` procedure from the next section on
all files encrypted with the rotated key by applying this update delta
token to them.

Make sure that you keep this update token delta secret, if it leaks,
it will neutralize the forward secrecy and post-compromise security
properties of this protocol for the current and the previous key.

```sh
% klutshnik rotate <keyname> [<ltsigkey] >pubkey-and-delta
```

### Update a file with a rotated key

Files encrypted with the key referenced by the key name can be
bulk-updated by piping:
 - the update delta token from the rotate operation described in the
   previous section, and
 - the list of paths pointing at these files
into the CLI client.

This operation does not require a long-term signing key. Furthermore
this is an offline operation, there is no need for connectivity to the
KMS', In fact this operation can run on the storage server itself.

```sh
% klutshnik update <delta  <files2update
```

Warning: Make sure that you keep the update token delta secret, if it
leaks, it will neutralize the forward secrecy and post-compromise
security properties of this protocol for the current and the previous
key.

### Refresh local key metadata

The client keeps a local cache of some key related metadata:

 - as the public key,
 - the current epoch,
 - the threshold,
 - the owner public key, and
 - the shares that can be combined into the public key.

When a client rotates a key, some of these values change. Other
clients should refresh their own local copy of these by running a
refresh operation.

```sh
% klutshnik refresh <keyname> [<ltsigkey] >pk
```

This operation will output the current public key associated with the
keyname on standard output.

### Delete a key

This operation deletes the shares of the key referenced by the
`keyname` if the provided (either in the configuration file or on
standard input) long-term signing key is authorized to do so.

```sh
% klutshnik delete <keyname> [<ltsigkey]
```

### Authorize a user

Adding additional users and authorization permissions can be done by
using the `adduser` operation. The parameters to this operation are
 - the `keyname` to which a new user is added,
 - the base64 encoded long-term public signing-key,
 - and a list of permissions, separated by commas: owner,decrypt,update,delete

The user executing this operation must be in possession of a long-term
signing-key, which has the `owner` permission.

```sh
% klutshnik adduser <keyname> <b64 pubkey> <owner,decrypt,update,delete> [<ltsigkey]
```

The output of this operation is the base64 encoded serialized setup
related to this key. This data is they keyid, and the `[server]`
section with `ltsigkey` and `ssl_cert` files inlined. This "token"
must be passed to the user who has been authorized, so they can
`import` this into their own configuration.

### Delete a user

A user which has the `owner` permission associated with their
long-term signing key associated with a key referenced by the
`keyname` can delete an user specified by their public key.

```sh
% klutshnik deluser <keyname> <b64 pubkey> [<ltsigkey]
```

### List authorizations of users

A user which has the `owner` permission associated with their
long-term signing key associated with a key referenced by the
`keyname` can list all authorized users and their permissions.

```sh
% klutshnik listusers <keyname> [<ltsigkey]
```

### Import Foreign Key Setup

Non-owner users who have been authorized - unless they have the same
`id_salt` value and the same `[server]` section in their config as the
owner -, must import the setup of the owner into their local
`keystore`. The setup is exported by the owner automatically when
running an `adduser` operation, this output must be passed to the user
being authorized as follows:

```sh
% klutshnik import <keyid> <KLTCFG-...b64...> [<ltsigkey]
```

This command automatically runs internally a `refresh` operation to
query the current epoch and public key related to this key. All this
is stored in the local `keystore` of the user.

# SECURITY CONSIDERATIONS

You **MUST** keep your delta update tokens private! Leaking them will
negate the forward secrecy and post-compromise security properties of
the whole scheme.

It is **RECOMMENDED** to store your private long-term signing key in a
dedicated secure storage instead of just having it in a file on your
disk pointed at the `ltsigkey_path` variable in your configuration
file. pwdsphinx provides native support for this.

Do not let any 3rd-party hold enough shares to achieve the threshold.

You **SHOULD** back up your configuration, especially the `id_salt`
and the names of the servers you are using, losing them means losing
access to your data.

# REPORTING BUGS

https://github.com/stef/klutshnik/issues/

# AUTHOR

Written by Stefan Marsiske.

# COPYRIGHT

Copyright © 2025 Stefan Marsiske.  License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.  There is NO WARRANTY, to the extent permitted by law.

# SEE ALSO

`https://klutshnik.info`

`klutshnik.cfg(5)`

`https://sphinx.pm`
