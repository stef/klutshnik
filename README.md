# GNU Klutshnik

Hello my name is Klyoovtuokmshnik, Styepanovich Klyoovtuokmshnik - but
my friends call me "Klutshnik" (Narrator: let me interject for a
moment, What you are referring to as Klutshnik, is in fact,
GNU/Klutshnik, or as I've recently taken to calling it, GNU plus
Klutshnik)

**Klutshnik** is a key management system for encrypting data at rest. It splits encryption keys across multiple servers so that no single server ever holds a complete key.

> **Warning:** This is beta software. It needs testing and is intended for experimentation, not production use.

## Also on Radicle

To clone this repo on [Radicle](https://radicle.xyz), run:
`rad clone rad:zogkw4qiTrH7rKVa89BrKo8z5miA`

## What Klutshnik Does

Klutshnik implements the full client and Key Management System (KMS) from the paper "[Verifiable Threshold Updatable Oblivious Key Management for Storage Systems" by Stanislaw Jarecki, Hugo Krawczyk, and Jason Resch](https://eprint.iacr.org/2024/1004).

To quote the above paper's abstract:

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
>
> > en/decryption key] is wrong (either due to computing error or to
> > adversarial action)

So, in a nutshell:

- You encrypt files locally, without needing to contact any servers.
- You contact a number (threshold) of servers who each contribute a piece of the key.
- You use the resulting key to decrypt the file.
- You can rotate keys periodically without re-encrypting your terabytes of data.

## Installation

### 1. Dependencies

You should install the following dependencies:

- [`libsodium`](https://libsodium.org/) and [pysodium](https://pypi.org/project/pysodium) for the cryptography primitives
- [`liboprf`](https://github.com/stef/liboprf) for supporting for Threshold Oblivious Pseudorandom Functions (OPRFs), the protocol that makes this all work.
- `Zig` to build the server.

To install `liboprf`:

```
# in directory $buildroot (where you want to install liboprf)
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

### 2. Building Klutshnik

```
# in directory $buildroot
git clone https://github.com/stef/klutshnik
cd klutshnik
make
sudo PREFIX=/usr make install
cd server
zig build
```

## Running Klutshnik

Once built, you can run a local test cluster to see how Klutshnik works.
To test also the update of keys, a minimum of
`2*(threshold-1)+1` shares is necessary. Hence, the minimum setup
requires 5 servers. If you don't have that many devices to run
Klutshnik servers on, just run a couple of them on the same device.

In the `test` directory, there is a fully-configured client-server
setup. If you have installed `libklutshnik` and the Python CLI client
(as described in the [client installation instruction](https://klutshnik.info/client_install.html)), and
built the Zig server (as described above), the following tests should work and give you an idea of how to use Klutshnik

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

In [example_session.md](./example_session.md), it shows an example of
the format encrypted files.

# References

- The main key management functionality is based on: [[https://eprint.iacr.org/2019/1275][Updatable Oblivious Key Management for Storage Systems]] by
  Jarecki, Krawczyk, and Resch.
- The Threshold OPRF is based on: [[https://eprint.iacr.org/2017/363][TOPPSS: Cost-minimal Password-Protected Secret Sharing based on Threshold OPRF]] by Jarecki, Kiayias, Krawczyk, and Xu.
- The key generation is based on: [[https://dl.acm.org/doi/10.1145/277697.277716][Simplified VSS and fast-track multiparty computations with applications to threshold cryptography]] by Gennaro, Rabin, and Rabin. It is fully specified in [[https://github.com/stef/liboprf/blob/master/docs/stp-dkg.txt][the liboprf STP DKG whitepaper]]
- The key update is based on the `Simple-Mult` protocol described in: [[https://dl.acm.org/doi/10.1145/277697.277716][Simplified VSS and fast-track multiparty computations with applications to threshold cryptography]] by Gennaro, Rabin, and Rabin. It is fully specified in [[https://github.com/stef/liboprf/blob/master/docs/stp-update.txt][the liboprf STP update whitepaper]]
- The files are encrypted using `crypto_secretbox()` by [[https://github.com/jedisct1/libsodium][libsodium]], using the `STREAM` protocol described in: [[https://eprint.iacr.org/2015/189][Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance]] by Viet Tung Hoang, Reza Reyhanitabar, Phillip Rogaway, and Damian Vizár

## Funding

This project is funded through [NGI0 Entrust](https://nlnet.nl/entrust), a fund
established by [NLnet](https://nlnet.nl) with financial support from the
European Commission's [Next Generation Internet](https://ngi.eu) program. Learn
more at the [NLnet project page](https://nlnet.nl/project/ThresholdOPRF).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)
[<img src="https://nlnet.nl/image/logos/NGI0_tag.svg" alt="NGI Zero Logo" width="20%" />](https://nlnet.nl/entrust)

I want to express my gratitude to my love, who endures me working and
rambling about this project. Peter Schwabe who invited me in 2022 to
the HACS workshop which was so inspiring like nothing before, which
spawned all this above. Trevor Perrin explained me how to implement a
tOPRF, and Hugo Krawczyk who was patient enough to answer many of my
ignorant questions. And Jonathan who helped me understand some tricky
part of the DKG.
