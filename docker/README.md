Klutshnik Demo Environment
==========================

This all should be in Docker Compose, but I deemed this enough for a tech demo

## KMS

Build the container:

`docker build . -t klutshnik-kms`

Run the container with name `kms1`:

`docker run --env KMS_NAME=kms1 -v "$(dirname $(pwd))"/config:/kms/klutshnik/config_host --rm -t klutshnik-kms`

This bind mounts the `docker/config` directory to the container and generates KMS public and private keys there.

The public key and the IP address is echoed to stdout, so the client can be appropriately configured.

You should lauch at least 5 containers from this image.

# Client

Build:

`docker build . -t klutshnik-client`

The client image is supposed to be used interactively:

`docker run --rm -it klutshnik-client /bin/sh`
