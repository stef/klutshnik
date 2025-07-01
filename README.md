# GNU Klutshnik

Hello my name is Klyoovtuokmshnik, Styepanovich Klyoovtuokmshnik - but
my friends call me "klutshnik" (Narrator: let me interject for a
moment, What you are referring to as Klutshnik, is in fact,
GNU/Klutshnik, or as I've recently taken to calling it, GNU plus
Klutshnik)

## Also on Radicle

To clone this repo on [Radicle](https://radicle.xyz), simply run:

  `rad clone rad:zogkw4qiTrH7rKVa89BrKo8z5miA`

# WARNING

WARNING! this is beta quality software, it needs testing, it is intended for
interested parties to poke at and play with it. It is not intended for serious
use yet.

# Verifiable Threshold Updatable Oblivious Key Management for Storage Systems

This project implements the full VTUOKMS client and KMS from:

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
> KMS. Additionally, and in contrast to traditional KMS, our solution
> supports public key encryption and dispenses with any interaction
> with the KMS for data encryption (only decryption by the client
> requires such communication).

One thing that is missing from the above, is the "V" in "VTUOKMS"
which:

> provides verifiability, namely, the ability of KMS to prove to C
> that the [calculated en/decryption key] is indeed the value that
> results from computing the OPRF on the client-provided object
> identifier. This prevents data loss that occurs if the [calculated
> en/decryption key] is wrong (either due to computing error or to
> adversarial action)

# Dependencies

This code depends on liboprf[1], libsodium[2], pysodium[3]

[1] https://github.com/stef/liboprf/
[2] https://github.com/jedisct1/libsodium
[2] https://github.com/stef/pysodium

# Building

You need to install zig, libsodium-dev, liboprf, pyoprf and pysodium, with
whatever tools your OS provides you with.

## liboprf

Install libsodium with development files from your favorite package repository.

```
# in directory $buildroot
git clone https://github.com/stef/liboprf/
cd liboprf
# you can use the PREFIX environment variable to set the install location to a writable directory
export PREFIX=/path/preferred/oprf/location
make install
# ldconfig
# go back to $buildroot
cd ..

pip install pyoprf
```

## build Klutshnik

```
# in directory $buildroot
git clone https://github.com/stef/klutshnik
cd klutshnik
make
sudo PREFIX=/usr make install
cd server
zig build
```

## testing

In order to test also the update of keys, a minimum of
`2*(threshold-1)+1` shares is necessary. Hence the minimum setup
requires 5 servers. If you don't have that many devices to run
klutshnik servers on, just run a couple of them on the same device.

In the `test` directory there is a fully configured client/server (3-out-of-5)
setup. If you have installed libklutshnik and the python cli client, and built
the zig server, the following should work (and give you an idea how to use
this):

```sh
% cd test/servers
% ./start-servers.sh

# switch to a different terminal and go to klutshnik/test
# create the key
% klutshnik create "keyid1"
KLCPK-XhIO9gsXc0EJGlFFgLxlpsVE39pk3gRgzKkPg4gbgg0AAAAA9MxKACsmwEEfbMdS4tf8KrYM5h/w2FRcAZ0/4pRK0GQ=

# encrypt a message (this one only needs the public key from above)
% echo "attack at dawn" | klutshnik encrypt KLCPK-XhIO9gsXc0EJGlFFgLxlpsVE39pk3gRgzKkPg4gbgg0AAAAA9MxKACsmwEEfbMdS4tf8KrYM5h/w2FRcAZ0/4pRK0GQ= >/tmp/klutshniked

# decrypt the message (this one needs the key from the klutshnik server)
% klutshnik decrypt </tmp/klutshniked

# update the key on the klutshnik server
% klutshnik rotate "keyid1"
KLCPK-XhIO9gsXc0EJGlFFgLxlpsVE39pk3gRgzKkPg4gbgg0AAAABkD+jW5DoYBln2WJQ74gySEWhtM4bxbyJkeDgTcpNLVA=
KLCDELTA-XhIO9gsXc0EJGlFFgLxlpsVE39pk3gRgzKkPg4gbgg0AAAABk4hPN4VKb6lxeZO0hXEx1e/iGWQvYAIXQvu2pbIrQQQ=

# update the encryption on the encrypted file
% { echo "KLCDELTA-XhIO9gsXc0EJGlFFgLxlpsVE39pk3gRgzKkPg4gbgg0AAAABk4hPN4VKb6lxeZO0hXEx1e/iGWQvYAIXQvu2pbIrQQQ="; \
    echo "/tmp/klutshniked" } | klutshnik update

# decrypt with the new key
% klutshnik decrypt </tmp/klutshniked

# list who is authorized to operate on this key
% klutshnik listusers "keyid1"

# add a user that can update keys, but nothing else
% klutshnik adduser keyid1 13lty/jQszJ1Xn5krTC2kltvPJDMqb4bqk3jgZxR430= update
the newly authorized client must run:
klutshnik import "some-keyname" KLTCFG-<long base64 string>

# check that this user has been added
% klutshnik listusers "keyid1"

# remove this user again
% klutshnik deluser keyid1 13lty/jQszJ1Xn5krTC2kltvPJDMqb4bqk3jgZxR430=

# check that user has been removed
% klutshnik listusers "keyid1"

# delete the key
% klutshnik delete "keyid1"

# fail to decrypt the file without a key.
% klutshnik decrypt </tmp/klutshniked

# switch to the other console running the servers and quit them by pressing ^c
```

# example session

```
% klutshnik create keyid1
KLCPK-XhIO9gsXc0EJGlFFgLxlpsVE39pk3gRgzKkPg4gbgg0AAAAAUjWZfmo4B3a3i+Ii+KMS7L5d/vMyxpMUEvUMjJPWAQM=
% echo "HELLO world" | klutshnik encrypt KLCPK-XhIO9gsXc0EJGlFFgLxlpsVE39pk3gRgzKkPg4gbgg0AAAAAUjWZfmo4B3a3i+Ii+KMS7L5d/vMyxpMUEvUMjJPWAQM= >/tmp/encrypted
% xxd /tmp/encrypted
00000000: 5e12 0ef6 0b17 7341 091a 5145 80bc 65a6  ^.....sA..QE..e.
00000010: c544 dfda 64de 0460 cca9 0f83 881b 820d  .D..d..`........
00000020: 0000 0000 fc2f 2e5b e52f 341f 0874 6771  ...../.[./4..tgq
00000030: 0174 aba4 b489 44ff dd0e f291 5502 5ee6  .t....D.....U.^.
00000040: 3de7 a93b 63f2 22c7 886d 816b b26a 8447  =..;c."..m.k.j.G
00000050: 1aa7 2b81 36e1 3329 f517 2658 3ad1 7100  ..+.6.3)..&X:.q.
00000060: e5c1 8560 395b 1957 3c00 7176            ...`9[.W<.qv

% klutshnik decrypt </tmp/encrypted
HELLO world
% klutshnik rotate "keyid1"
KLCPK-XhIO9gsXc0EJGlFFgLxlpsVE39pk3gRgzKkPg4gbgg0AAAABkD+jW5DoYBln2WJQ74gySEWhtM4bxbyJkeDgTcpNLVA=
KLCDELTA-XhIO9gsXc0EJGlFFgLxlpsVE39pk3gRgzKkPg4gbgg0AAAABk4hPN4VKb6lxeZO0hXEx1e/iGWQvYAIXQvu2pbIrQQQ=
% printf "KLCDELTA-XhIO9gsXc0EJGlFFgLxlpsVE39pk3gRgzKkPg4gbgg0AAAABk4hPN4VKb6lxeZO0hXEx1e/iGWQvYAIXQvu2pbIrQQQ=\n/tmp/encrypted" | klutshnik update keyid1
% xxd /tmp/encrypted
00000000: 5e12 0ef6 0b17 7341 091a 5145 80bc 65a6  ^.....sA..QE..e.
00000010: c544 dfda 64de 0460 cca9 0f83 881b 820d  .D..d..`........
00000020: 0000 0001 bc9b 0104 283b 7aa8 2939 d0f5  ........(;z.)9..
00000030: 89a8 eda3 f665 995f 499b d895 04da 9238  .....e._I......8
00000040: 5db1 8d05 63f2 22c7 886d 816b b26a 8447  ]...c."..m.k.j.G
00000050: 1aa7 2b81 36e1 3329 f517 2658 3ad1 7100  ..+.6.3)..&X:.q.
00000060: e5c1 8560 395b 1957 3c00 7176            ...`9[.W<.qv

% klutshnik decrypt </tmp/encrypted
HELLO world
```

# File formats

Encrypted files have the following structure:

```
16 bytes keyid
4  bytes epoch
32 bytes w value
12 byte nonce-half
every 64KB
    64 kBytes ciphertext (chacha20)
    16 bytes MAC (poly1305)
```
You can see in the above example session, that after key-update only
the w value is changed, nothing else.

# References

The main functionality is based on the UOKMS construction of the
https://eprint.iacr.org/2019/1275

    "Updatable Oblivious Key Management for Storage Systems"
    by Stanislaw Jarecki, Hugo Krawczyk, and Jason Resch

The Threshold OPRF is based on: https://eprint.iacr.org/2017/363

    "TOPPSS: Cost-minimal Password-Protected Secret Sharing based on Threshold OPRF"
    by Stanislaw Jarecki, Aggelos Kiayias, Hugo Krawczyk, and Jiayu Xu

Within this, the DKG is based on

    R. Gennaro, M. O. Rabin, and T. Rabin. "Simplified VSS and fact-track
    multiparty computations with applications to threshold cryptography" In B.
    A. Coan and Y. Afek, editors, 17th ACM PODC, pages 101–111. ACM, June /
    July 1998 and is fully specified in liboprf/docs/stp-dkg.txt

The key-update is based on:

    Fig. 2 from "Simplified VSS and fact-track multiparty computations with
    applications to threshold cryptography" by R. Gennaro, M. O. Rabin, and T.
    Rabin. This is fully specified in liboprf/docs/stp-update.txt

The files are encrypted using `crypto_secretbox()` by libsodium
https://github.com/jedisct1/libsodium, using the STREAM construction
https://eprint.iacr.org/2015/189:

    "Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance"
    by Viet Tung Hoang, Reza Reyhanitabar, Phillip Rogaway, and Damian Vizár
