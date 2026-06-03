#!/bin/sh

rm -rf $(pwd)/configuration-client/log
mkdir -p $(pwd)/configuration-client/log

docker run \
  --user "$(id -u):$(id -g)" \
  -v "$(pwd)/configuration-client:/opt/mount:rw" \
  --rm \
  --entrypoint cp spidclient:latest-KC /usr/src/app/.env-example /opt/mount/.env-example

# TODO Ricavare l'url di nginx dal docker-compose-nginx.yaml; eventualmente gestire altre variabili (es. url keycloack, ecc)
cat $(pwd)/configuration-client/.env-example \
  | sed 's,createSpidSpTestIdP = false,createSpidSpTestIdP = true,g' \
  | sed 's,https://yourdomain.com/spid-sp-test.xml,https://spid-nginx:443/spid-sp-test.xml,g' \
  > $(pwd)/configuration-client/.env

docker run \
  --net=host \
  -w /usr/src/app \
  -ti --rm \
  -v "$(pwd)/configuration-client/.env:/usr/src/app/.env:ro" \
  -v "$(pwd)/configuration-client/log:/usr/src/app/log:rw" \
  spidclient:latest-KC
