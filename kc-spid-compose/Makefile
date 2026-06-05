# Environment variables
.EXPORT_ALL_VARIABLES:
SPID_DB_ROOT_PASSWORD = keycloak-root
SPID_DB_SCHEMA = keycloak
SPID_DB_USERNAME = keycloak
SPID_DB_PASSWORD = keycloak-password
SPID_KC_VERSION = 26.6.1
SPID_KC_ADMIN_USERNAME = admin
SPID_KC_ADMIN_PASSWORD = admin


# Basic commands

_sleep:
	sleep 10

build-provider-jar:
	rm -rf ${PWD}/provider/spid-provider.jar
	make -C ${PWD}/.. build
	cp ${PWD}/../target/spid-provider.jar ${PWD}/provider/spid-provider.jar


# Test commands

test-responses:
	./run-spid-sp-test-responses.sh


# Resets docker compose, deletes files and artifacts

clean: reset-mariadb reset-mysql reset-postgres
	rm -rf ${PWD}/certificates/spid-sp-test-idp ${PWD}/certificates/keycloak-server.* ${PWD}/certificates/nginx.*
	rm -rf ${PWD}/configuration-client/.env
	rm -rf ${PWD}/provider/*.jar
	rm -rf ${PWD}/tests/spid-sp-test.xml


# Common entities configuration

init:
	./create-configuration-client-docker-image.sh
	./create-self-signed-certificates.sh
	./create-spid-sp-test-docker-image.sh
	./create-spid-sp-test-metadata-certificates.sh



# Mariadb commands

mariadb:
	SPID_KC_DB_TYPE=mariadb docker compose \
		-f docker-compose-networks.yaml \
		-f docker-compose-mariadb.yaml \
		-f docker-compose-keycloak.yaml \
		-f docker-compose-nginx.yaml \
		up -d --wait
	sleep 10s
	./run-configuration-client-docker.sh

reset-mariadb:
	SPID_KC_DB_TYPE=mariadb docker compose \
		-f docker-compose-networks.yaml \
		-f docker-compose-mariadb.yaml \
		-f docker-compose-keycloak.yaml \
		-f docker-compose-nginx.yaml \
		down -v

setup-mariadb: clean init build-provider-jar mariadb

refresh-mariadb: reset-mariadb build-provider-jar mariadb

test-mariadb: refresh-mariadb test-responses

full-mariadb: setup-mariadb test-responses



# Mysql commands

mysql:
	SPID_KC_DB_TYPE=mysql docker compose \
		-f docker-compose-networks.yaml \
		-f docker-compose-mysql.yaml \
		-f docker-compose-keycloak.yaml \
		-f docker-compose-nginx.yaml \
		up -d --wait
	sleep 10s
	./run-configuration-client-docker.sh

reset-mysql:
	SPID_KC_DB_TYPE=mysql docker compose \
		-f docker-compose-networks.yaml \
		-f docker-compose-mysql.yaml \
		-f docker-compose-keycloak.yaml \
		-f docker-compose-nginx.yaml \
		down -v

setup-mysql: clean init build-provider-jar mysql

refresh-mysql: reset-mysql build-provider-jar mysql

test-mysql: refresh-mysql test-responses

full-mysql: setup-mysql test-responses



# Postgres commands

postgres:
	SPID_KC_DB_TYPE=postgres docker compose \
		-f docker-compose-networks.yaml \
		-f docker-compose-postgres.yaml \
		-f docker-compose-keycloak.yaml \
		-f docker-compose-nginx.yaml \
		up -d --wait
	sleep 10s
	./run-configuration-client-docker.sh

reset-postgres:
	SPID_KC_DB_TYPE=postgres docker compose \
		-f docker-compose-networks.yaml \
		-f docker-compose-postgres.yaml \
		-f docker-compose-keycloak.yaml \
		-f docker-compose-nginx.yaml \
		down -v

setup-postgres: clean init build-provider-jar postgres

refresh-postgres: reset-postgres build-provider-jar postgres

test-postgres: refresh-postgres test-responses

full-postgres: setup-postgres test-responses
