reset-mariadb:
	./reset-mariadb-compose.sh

reset-mysql:
	./reset-mysql-compose.sh

reset-postgres:
	./reset-postgres-compose.sh

clean: reset-mariadb reset-mysql reset-postgres
	rm -rf ./certificates/spid-sp-test-idp ./certificates/keycloak-server.* ./certificates/nginx.*
	rm -rf ./configuration-client/.env
	rm -rf ./provider/*.jar
	rm -rf ./tests/spid-sp-test.xml

init:
	./create-configuration-client-docker-image.sh
	./create-self-signed-certificates.sh
	./create-spid-sp-test-docker-image.sh
	./create-spid-sp-test-metadata-certificates.sh

build-provider:
	./build-provider-jar.sh

mariadb:
	SPID_KC_DB_TYPE=mariadb docker compose -f docker-compose-networks.yaml -f docker-compose-mariadb.yaml -f docker-compose-keycloak.yaml -f docker-compose-nginx.yaml up -d --wait
	sleep 10s
	./run-configuration-client-docker.sh

setup-mariadb: clean init build-provider mariadb

refresh-mariadb: reset-mariadb build-provider mariadb

mysql:
	SPID_KC_DB_TYPE=mysql docker compose -f docker-compose-networks.yaml -f docker-compose-mysql.yaml -f docker-compose-keycloak.yaml -f docker-compose-nginx.yaml up -d --wait
	sleep 10s
	./run-configuration-client-docker.sh

setup-mysql: clean init build-provider mysql

refresh-mysql: reset-mysql build-provider mysql

postgres:
	SPID_KC_DB_TYPE=postgres docker compose -f docker-compose-networks.yaml -f docker-compose-postgres.yaml -f docker-compose-keycloak.yaml -f docker-compose-nginx.yaml up -d --wait
	sleep 10s
	./run-configuration-client-docker.sh

setup-postgres: clean init build-provider postgres

refresh-postgres: reset-postgres build-provider postgres

test:
	./run-spid-sp-test-responses.sh

test-mariadb: refresh-mariadb test

test-mysql: refresh-mysql test

test-postgres: refresh-postgres test

full-mariadb: setup-mariadb test

full-mysql: setup-mysql test

full-postgres: setup-postgres test
