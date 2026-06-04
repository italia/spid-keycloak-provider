clean:
  echo Cleaning docker compose and artifacts...
  ./reset-mariadb-compose.sh
  ./reset-mysql-compose.sh
  ./reset-postgres-compose.sh
  rm -rf ./certificates/spid-sp-test-idp ./certificates/keycloak-server.* ./certificates/nginx.*
  rm -rf ./configuration-client/.env
  rm -rf ./provider/*.jar
  rm -rf ./tests/spid-sp-test.xml
  echo Cleaning completed.

init:
  echo Initializing environment...
  ./create-configuration-client-docker-image.sh
  ./create-self-signed-certificates.sh
  ./create-spid-sp-test-docker-image.sh
  ./create-spid-sp-test-metadata-certificates.sh

provider:
  echo Building provider...
  ./build-provider-jar.sh

mariadb:
  echo Building compose...
  SPID_KC_DB_TYPE=mariadb docker compose \
    -f docker-compose-networks.yaml \
    -f docker-compose-mariadb.yaml \
    -f docker-compose-keycloak.yaml \
    -f docker-compose-nginx.yaml \
    up -d --wait
  echo Waiting for services...
  sleep 10s
  echo Running configuration client...
  ./run-configuration-client-docker.sh
  echo Done.

setup-mariadb: clean init provider mariadb

mysql:
  echo Building compose...
  SPID_KC_DB_TYPE=mysql docker compose \
    -f docker-compose-networks.yaml \
    -f docker-compose-mysql.yaml \
    -f docker-compose-keycloak.yaml \
    -f docker-compose-nginx.yaml \
    up
  echo Waiting for services...
  sleep 10s
  echo Running configuration client...
  ./run-configuration-client-docker.sh
  echo Done.

setup-mysql: clean init provider mysql

postgres:
  echo Building compose...
  SPID_KC_DB_TYPE=postgres docker compose \
    -f docker-compose-networks.yaml \
    -f docker-compose-postgres.yaml \
    -f docker-compose-keycloak.yaml \
    -f docker-compose-nginx.yaml \
    up -d --wait
  echo Waiting for services...
  sleep 10s
  echo Running configuration client...
  ./run-configuration-client-docker.sh
  echo Done.

setup-postgres: clean init provider postgres

test:
  ./run-spid-sp-test-responses.sh

full-mariadb: setup-mariadb test

full-mysql: setup-mysql test

full-postgres: setup-postgres test
