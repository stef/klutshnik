This all should be in Docker Compose, but I deemed this enough for a tech demo

## KMS

Run the container with name `kms1`:

`docker run --env KMS_NAME=kms1 -v "$(dirname $(pwd))"/config:/kms/klutshnik/config_host --rm -t klutshnik-kms`

This bind mounts the `docker/config` directory to the container and generates KMS public and private keys there.

The public key and the IP address is echoed to stdout, so the client can be appropriately configured.

