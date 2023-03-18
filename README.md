# Klutshnik

Hello my name is Klyoovtuokmshnik, Styepanovich Klyoovtuokmshnik but
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

This code depends on liboprf[1], libsodium[2], pysodium[3], noise-c[4] and dissononce[5].

It is to be expected that the dependencies noise-c and dissononce will
be eliminated by specific implementation of the Noise XK handshake
using libsodium.

Furthermore the authentication tokens will be automatically stored and
retrieved from an opaque-store[6].

[1] https://github.com/stef/liboprf/
[2] https://github.com/jedisct1/libsodium
[3] https://github.com/stef/pysodium
[4] https://github.com/stef/pysodium
[5] https://github.com/tgalal/dissononce
[6] https://github.com/stef/opaque-store/

# Building

You need to install libsodium-dev, dissononce and pysodium, with
whatever tools your OS provides you with.

## liboprf

```
# in directory $buildroot
git clone https://github.com/stef/liboprf/
cd liboprf
# have a look in the makefile to be sure you trust the next step with root permissions
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
git clone https://github.com/rweather/noise-c
cd noise-c
./autogen.sh
./configure --with-libsodium --with-openssl
make
cd ..
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
./genkey.py client.tmp | base64 -d >>client.tmp
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

Finally you can start the servers, a simple script `start-servers.sh`
is provided which starts 5 servers on localhost with the keys
generated before.

You can now try to run the commands from the:

# example session

```
% ./client.py -c genkey -t 3
keyid e2d0ee2a082920dd02822737ac7267b4
% echo "hello world" | ./client.py -c encrypt -k e2d0ee2a082920dd02822737ac7267b4 >/tmp/encrypted
% xxd /tmp/encrypted
00000000: bd9c 7f46 7eb4 1469 900d e1d4 6ed1 28bc  ...F~..i....n.(.
00000010: 3a13 6f99 b648 3a4d 1076 8629 68b2 1a70  :.o..H:M.v.)h..p
00000020: 50de 9ca9 5af1 481a 9f36 1b8e 664b ee17  P...Z.H..6..fK..
00000030: 66d6 0cc8 6112 3e6e c234 4f80 5e08 0acd  f...a.>n.4O.^...
00000040: 100d 7c72 3ad8 46d3 4a82 afb0            ..|r:.F.J...
% ./client.py -c decrypt </tmp/encrypted
hello world%
% echo -n /tmp/encrypted | ./client.py -c update -k e2d0ee2a082920dd02822737ac7267b4
% xxd /tmp/encrypted
00000000: e2d0 ee2a 0829 20dd 0282 2737 ac72 67b4  ...*.) ...'7.rg.
00000010: 945c b880 5019 40c2 8342 fbd9 22f7 ac44  .\..P.@..B.."..D
00000020: 67e0 deec 19af f34e fd89 0594 511d 750e  g......N....Q.u.
00000030: a4a7 9353 b5f3 f99b c9df 1b66 57b8 7758  ...S.......fW.wX
00000040: a177 9f7c ca38 b93c 29b9 eadb f7b6 5adc  .w.|.8.<).....Z.
00000050: 48b3 c23c 1fd7 775d 5db3 2502 4711 03a3  H..<..w]].%.G...
00000060: c561 85                                  .a.
% ./client.py -c decrypt </tmp/encrypted
hello world%
```

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

Within this, the DKG is based on

    "Secure Distributed Key Generation for Discrete-Log Based Cryptosystems"
    by Rosario Gennaro, Stanislaw Jarecki, Hugo Krawczyk, Tal Rabin

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

provided by noise-c: https://github.com/rweather/noise-c and
dissononce: https://github.com/tgalal/dissononce

The files are encrypted using `crypto_secretbox()` by libsodium
https://github.com/jedisct1/libsodium, using the STREAM construction
https://eprint.iacr.org/2015/189:

    "Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance"
    by Viet Tung Hoang, Reza Reyhanitabar, Phillip Rogaway, and Damian Vizár
