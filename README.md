# GNU Klutshnik

Hello my name is Klyoovtuokmshnik, Styepanovich Klyoovtuokmshnik - but
my friends call me "klutshnik" (Narrator: let me interject for a
moment, What you are referring to as Klutshnik, is in fact,
GNU/Klutshnik, or as I've recently taken to calling it, GNU plus
Klutshnik)

# WARNING

WARNING! this is very early alpha-grade proof of concept, it is
intended for interested parties to poke at and play with it. It is not
intended for any even half-serious use yet.

# Verifiable Threshold Updatable Oblivious Key Management for Storage Systems

This is a PoC implementing the full VTUOKMS from

https://eprint.iacr.org/2019/1275
"Updatable Oblivious Key Management for Storage Systems"
by Stanislaw Jarecki, Hugo Krawczyk, and Jason Resch

OK, tl;dr, wth is a vtuokms???5? To quote the above paper's abstract:

> [...] system, that builds on Oblivious Pseudorandom Functions
> (OPRF), hides keys and object identifiers from the KMS, offers
> unconditional security for key transport, provides key
> verifiability, reduces storage, and more. Further, we show how to
> provide all these features in a distributed threshold implementation
> that enhances protection against server compromise.

> We extend this system with updatable encryption capability that
> supports key updates (known as key rotation) so that upon the
> periodic change of OPRF keys by the KMS server, a very efficient
> update procedure allows a client of the KMS service to
> non-interactively update all its encrypted data to be decryptable
> only by the new key. This enhances security with forward and
> post-compromise security, namely, security against future and past
> compromises, respectively, of the client’s OPRF keys held by the
> KMS. Additionally, and in contrast to tra- ditional KMS, our
> solution supports public key encryption and dispenses with any
> interaction with the KMS for data encryption (only decryption by the
> client requires such communication).

One thing that is missing from the above, is the "V" in "VTUOKMS"
which:

> provides verifiability, namely, the ability of KmS to prove to C
> that the [calculated en/decryption key] is indeed the value that
> results from computing the OPRF on the client-provided object
> identifier. This prevents data loss that occurs if the [calculated
> en/decryption key] is wrong (either due to computing error or to
> adversarial action)

# Dependencies

This code depends on liboprf[1], libsodium[2], pysodium[3], hacl-star[4] and dissononce[5].

Furthermore the authentication tokens will be automatically stored and
retrieved from an opaque-store[6].

[1] https://github.com/stef/liboprf/
[2] https://github.com/jedisct1/libsodium
[3] https://github.com/stef/pysodium
[4] https://github.com/project-everest/hacl-star
[5] https://github.com/tgalal/dissononce
[6] https://github.com/stef/opaque-store/

# Building

You need to install libsodium-dev, dissononce and pysodium, with
whatever tools your OS provides you with.

First of all you need to get hacl-star and export an environment
variable pointing to it:

```
git clone https://github.com/project-everest/hacl-star
export HACL_HOME=$(pwd)/hacl-star
```

Only some header files are needed, so you don't have to build it.

Then the other deps:

## liboprf

Install libsodium with development files from your favorite package repository.

```
# in directory $buildroot
git clone https://github.com/stef/liboprf/
cd liboprf
# you can use the PREFIX environment variable to set the install location to a writable directory
export PREFIX=/path/preferred/oprf/location
make install
cp liboprf.so /usr/lib # or wherever your OS stores libs
# on glibc based systems also run:
# ldconfig
# go back to $buildroot
cd ..
```

## build Klutshnik

```
# in directory $buildroot
git clone https://github.com/stef/klutshnik
cd klutshnik
export OPRF_HOME=$PREFIX # match OPRF install location from previous step
make
```

## testing

In order to test also the update of keys, a minimum of
`2*(threshold-1)+1` shares is necessary. Hence the minimim setup
requires 5 servers (possibly the number is 3 actually, this needs
testing/confirmation). If you don't have that many devices to run
klutshnik servers on, just run a couple of them on the same device.

For each klutshnik server we need to create each their own keypair
using:

```
for i in $(seq 0 4); do ./genkey.py ksm$i.key; done
```

The public keys printed to standard output from above must be set
accordingly in the file `klutshnik.cfg`

We also need to create a client key:

```
./genkey.py client.tmp | tee client.pub | base64 -d >>client.tmp
base64 <client.tmp >client.key
rm client.tmp
```

Some directories need to be created. The default `keys/` can be
changed in `klutshnik.cfg` is used by the client to store its public
keys:

```
mkdir keys
```

and `shares` is hardcoded and relative where the kms server is
running. This directory is used by the kms to store the shares:

```
mkdir shares
```

On the servers you also need a `config` directory, which contains the
file `authorized_keys`, this is similar to the `authorized_keys` file in
ssh. This file contains the public key key of the client in base64
format and a user/client name separated by a space from the key.

```
mkdir config
{ head -1 client.pub | tr -d '\n' ; echo " myusername" }
```

The file `client.pub` was created above with the genkey.py script.

This `config` directory must also contain a file `auth.key` which is
just 32 bytes of good entropy:

```
dd if=/dev/random of=config/auth.key bs=1 count=32
```

This `auth.key` must be the same for all servers, this is the key that
creates and verifies the authorization tokens. Which brings us to the
tool `macaroon`. This is a simple command line tool to create and
manipulate macaroons, the tokens klutshnik uses for
authorization. Currently even for creating new keys you need an
authorization token, a so called godmode token, you can create it like this:

```
./macaroon create -a config/auth.key
```

the file `config/auth.key` is the authorization key that is stored on
all servers. the output of this command is a base64 encoded token,
which you can put into your `klutshnik.cfg` as `authtok="<the token>"`
to be able to use your client with the servers. In later versions of
klutshnik support for these godmode token will be removed, if they
leak to an attacker they can do anything... For more info on the
`macaroon` tool see the section below.

Finally you can start the servers, a simple script `start-servers.sh`
is provided which starts 5 servers on localhost with the keys
generated before.

You can now try to run the commands from the:

# example session

```
% ./client.py -c genkey -t 3
keyid e2d0ee2a082920dd02822737ac7267b4
% echo "HELLO world" | ./client.py -c encrypt -k 717e7e76565d68c81c843aea57a8fe7a >/tmp/encrypted
% xxd /tmp/encrypted
00000000: 717e 7e76 565d 68c8 1c84 3aea 57a8 fe7a  q~~vV]h...:.W..z
00000010: ca8e 5548 f778 27c6 f844 5c32 2253 f57e  ..UH.x'..D\2"S.~
00000020: 774e f66c b78f 6117 e430 f9cc 1631 bc2b  wN.l..a..0...1.+
00000030: 34b2 df54 89a6 d695 a24d b86a 1bac 31f8  4..T.....M.j..1.
00000040: c05a 05e8 e25e 0f26 3a28 644c 676f 44ba  .Z...^.&:(dLgoD.
00000050: cf7c 0152 016c 82ba                      .|.R.l..

% ./client.py -c decrypt </tmp/encrypted
hello world%
% echo -n /tmp/encrypted | ./client.py -c update -k 717e7e76565d68c81c843aea57a8fe7a
% xxd /tmp/encrypted
00000000: 717e 7e76 565d 68c8 1c84 3aea 57a8 fe7a  q~~vV]h...:.W..z
00000010: 641f 1083 f7c2 89fa 5ff5 089e 1f3f e193  d......._....?..
00000020: 784c 86a7 8064 b7a2 98c1 1ece dc2a e70f  xL...d.......*..
00000030: 34b2 df54 89a6 d695 a24d b86a 1bac 31f8  4..T.....M.j..1.
00000040: c05a 05e8 e25e 0f26 3a28 644c 676f 44ba  .Z...^.&:(dLgoD.
00000050: cf7c 0152 016c 82ba                      .|.R.l..

% ./client.py -c decrypt </tmp/encrypted
HELLO world
```
# Macaroon tool

If you want to look at your macaroon, you can do so by passing it on
standard input to

```
echo -n "<the token>" | ./macaroon dump
```

The full capabilities of this tool are as follows:

```
./macaroon create -a <authkey> [-u uid] [-e <seconds>] [-k <keyid>] [-p <pubkey>] [-o <privlevel>]
./macaroon dump
./macaroon verify -a <authkey>
./macaroon narrow [uid] [-e <seconds>] [-k <keyid>] [-p <pubkey>] [-o <privlevel>]
```

TODO finish documenting this.


# File formats

Encrypted files have the following structure:

```
16 bytes keyid
32 bytes w value
12 byte nonce-half
every 64KB
    64 kBytes ciphertext (chacha20)
    16 bytes MAC (poly1305)
```
You can see in the above example session, that after key-update only
the w value is changed, nothing else.

Public keys saved by the client in the directory `keys`, are named
with their keyid. Their contents has the following structure:

```
1 byte threshold
32 bytes ristretto255 public key
```

Shares stored by the KMS in the `shares` folder are named
`<keyid>-<share-sequence-number>` their contents has the following
structure:

```
1 byte index
32 bytes share
```

# References

The main functionality is based on the UOKMS construction of the
https://eprint.iacr.org/2019/1275

    "Updatable Oblivious Key Management for Storage Systems"
    by Stanislaw Jarecki, Hugo Krawczyk, and Jason Resch

The Threshold OPRF is based on: https://eprint.iacr.org/2017/363

    "TOPPSS: Cost-minimal Password-Protected Secret Sharing based on Threshold OPRF"
    by Stanislaw Jarecki, Aggelos Kiayias, Hugo Krawczyk, and Jiayu Xu

Within this, the DKG is based on

    "Secure Distributed Key Generation for Discrete-Log Based Cryptosystems"
    by Rosario Gennaro, Stanislaw Jarecki, Hugo Krawczyk, Tal Rabin

The key-update is based on:

    Fig. 2 from "Simplified VSS and fact-track multiparty computations
    with applications to threshold cryptography"
    by R. Gennaro, M. O. Rabin, and T. Rabin.


The Klutshnik servers use macaroons for authorization of request,
based on: https://research.google/pubs/pub41892/

    "Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud"
    by Arnar Birgisson Joe Gibbs Politz Úlfar Erlingsson Ankur Taly Michael Vrable Mark Lentczner

The opaque-store is based on https://eprint.iacr.org/2018/163

    "OPAQUE: An Asymmetric PAKE Protocol Secure Against Pre-Computation Attacks"
    by Stanislaw Jarecki, Hugo Krawczyk, and Jiayu Xu

All communication between the client and the Klutshnik servers and the
opaque-store are protected by Noise XK handshake patterns:
https://noiseprotocol.org/noise.html
https://noiseexplorer.com/patterns/XK/

provided by noise-star: https://github.com/Inria-Prosecco/noise-star/
and dissononce: https://github.com/tgalal/dissononce

It is to be noted, that noise-star by default depends on hacl-star for
basic cryptographic primitives: ChaChaPoly1305, Blake2b and x25519. But
in our variant, we replaced all binary dependencies to hacl-star with
equivalent function from libsodium.

The files are encrypted using `crypto_secretbox()` by libsodium
https://github.com/jedisct1/libsodium, using the STREAM construction
https://eprint.iacr.org/2015/189:

    "Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance"
    by Viet Tung Hoang, Reza Reyhanitabar, Phillip Rogaway, and Damian Vizár
