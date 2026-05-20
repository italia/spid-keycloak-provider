#!/bin/sh

docker run \
  --net=host \
  -w /usr/src/app \
  -ti --rm \
  -v "$(pwd)/configuration-client/.env:/usr/src/app/.env:ro" \
  -v "$(pwd)/configuration-client/log:/usr/src/app/log:rw" \
  spidclient:latest
