Klutshnik Demo Environment
==========================

This all should be in Docker Compose, but I deemed this enough for a tech demo

## KMS

(All commands assume CWD to be docker/kms)

Build the container:

`docker build . -t klutshnik-kms`

Run the container with name `kms1`:

`docker run --env KMS_NAME=kms1 -v "$(dirname $(pwd))"/config:/kms/klutshnik/config_host --rm -t klutshnik-kms`

This bind mounts the `docker/config` directory to the container and generates KMS public and private keys there.

The public key and the IP address is echoed to stdout, so the client can be appropriately configured.

You should launch at least 5 containers from this image.

## Client

(All commands assume CWD to be docker/client)

Build:

`docker build . -t klutshnik-client`

The client image is supposed to be used interactively. The startup script will drop you to a shell after generating klutshnik.cfg based on the files inside the host `config/` directory (previously generated by KMS's - don't forget to clean up!):

`docker run -v "$(dirname $(pwd))"/config:/client/klutshnik/config_host --rm -it klutshnik-client`

Inside the container:

```
cd python
./client.py -c genkey -t 3
```

This should connect to the KMS containters.
