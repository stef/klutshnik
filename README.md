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
`2*(threshold-1)+1` shares is necessary. Hence the minimim setup
requires 5 servers (possibly the number is 3 actually, this needs
testing/confirmation). If you don't have that many devices to run
klutshnik servers on, just run a couple of them on the same device.

# example session

```
% klutshnik create keyid1
% echo "HELLO world" | klutshnik encrypt keyid1 >/tmp/encrypted
% xxd /tmp/encrypted
00000000: 717e 7e76 565d 68c8 1c84 3aea 57a8 fe7a  q~~vV]h...:.W..z
00000010: ca8e 5548 f778 27c6 f844 5c32 2253 f57e  ..UH.x'..D\2"S.~
00000020: 774e f66c b78f 6117 e430 f9cc 1631 bc2b  wN.l..a..0...1.+
00000030: 34b2 df54 89a6 d695 a24d b86a 1bac 31f8  4..T.....M.j..1.
00000040: c05a 05e8 e25e 0f26 3a28 644c 676f 44ba  .Z...^.&:(dLgoD.
00000050: cf7c 0152 016c 82ba                      .|.R.l..

% klutshnik decrypt </tmp/encrypted
hello world%
% delta=$(klutshnik rotate "keyid1")
% echo -n /tmp/encrypted | klutshnik update keyid1 $delta
% xxd /tmp/encrypted
00000000: 717e 7e76 565d 68c8 1c84 3aea 57a8 fe7a  q~~vV]h...:.W..z
00000010: 641f 1083 f7c2 89fa 5ff5 089e 1f3f e193  d......._....?..
00000020: 784c 86a7 8064 b7a2 98c1 1ece dc2a e70f  xL...d.......*..
00000030: 34b2 df54 89a6 d695 a24d b86a 1bac 31f8  4..T.....M.j..1.
00000040: c05a 05e8 e25e 0f26 3a28 644c 676f 44ba  .Z...^.&:(dLgoD.
00000050: cf7c 0152 016c 82ba                      .|.R.l..

% klutshnik decrypt </tmp/encrypted
HELLO world
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
