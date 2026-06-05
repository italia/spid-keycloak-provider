# Environment variables
.EXPORT_ALL_VARIABLES:
SPID_DB_ROOT_PASSWORD = keycloak-root
SPID_DB_SCHEMA = keycloak
SPID_DB_USERNAME = keycloak
SPID_DB_PASSWORD = keycloak-password
SPID_KC_VERSION = 26.6.1
SPID_KC_ADMIN_USERNAME = admin
SPID_KC_ADMIN_PASSWORD = admin
NOW := $(shell date +"%Y%m%d_%H%M%S")


# Basic commands

_sleep:
	sleep 10

build-provider-jar:
	rm -rf ${PWD}/provider/spid-provider.jar
	make -C ${PWD}/.. build
	cp ${PWD}/../target/spid-provider.jar ${PWD}/provider/spid-provider.jar


# Test commands

test-metadata:
	mkdir -p ${PWD}/tests/report/$(NOW)_metadata
	docker run -ti --net=host --rm \
		-e IDP_CERT_PATH=/spid/ipd-certs \
		-v "${PWD}/certificates/spid-sp-test-idp:/spid/ipd-certs" \
		-v "${PWD}/tests/report/$(NOW)_metadata:/spid/html_report:rw" \
		italia/spid-sp-test:0.9.0-KC \
		--metadata-url "https://localhost:8443/auth/realms/spid/spid-sp-metadata" \
		--extra --report_format html --report-output-file html_report/

test-authn:
	mkdir -p ${PWD}/tests/report/$(NOW)_authn
	docker run -ti --net=host --rm \
		-e IDP_CERT_PATH=/spid/ipd-certs \
		-v "${PWD}/certificates/spid-sp-test-idp:/spid/ipd-certs" \
		-v "${PWD}/tests/report/$(NOW)_authn:/spid/html_report:rw" \
		italia/spid-sp-test:0.9.0-KC \
		--metadata-url "https://localhost:8443/auth/realms/spid/spid-sp-metadata" \
		--authn-url "https://localhost:8443/auth/realms/spid/protocol/openid-connect/auth?client_id=account&scope=openid&response_type=code&redirect_uri=https://localhost:8443/auth/realms/spid/account&state=12345&kc_idp_hint=spid-spid-sp-test" \
		--extra --report_format html --report-output-file html_report/

test-responses:
	mkdir -p ${PWD}/tests/report/$(NOW)_responses
	mkdir -p ${PWD}/tests/dumps/$(NOW)_responses
	docker run -ti --net=host --rm \
		-e IDP_CERT_PATH=/spid/ipd-certs \
		-v "${PWD}/certificates/spid-sp-test-idp:/spid/ipd-certs" \
		-v "${PWD}/tests/report/$(NOW)_responses:/spid/html_report:rw" \
		-v "${PWD}/tests/dumps/$(NOW)_responses:/spid/dumps:rw" \
		italia/spid-sp-test:0.9.0-KC \
		--metadata-url "https://localhost:8443/auth/realms/spid/spid-sp-metadata" \
		--authn-url "https://localhost:8443/auth/realms/spid/protocol/openid-connect/auth?client_id=account&scope=openid&response_type=code&redirect_uri=https://localhost:8443/auth/realms/spid/account&state=12345&kc_idp_hint=spid-spid-sp-test" \
		--extra --report_format html --report-output-file html_report/ \
		--test-response --response-html-dumps dumps/


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
