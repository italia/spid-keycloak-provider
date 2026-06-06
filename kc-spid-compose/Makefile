# Environment variables
.EXPORT_ALL_VARIABLES:
SPID_DB_ROOT_PASSWORD := keycloak-root
SPID_DB_SCHEMA := keycloak
SPID_DB_USERNAME := keycloak
SPID_DB_PASSWORD := keycloak-password
SPID_KC_VERSION := $(shell sed -n 's:.*<keycloak.version>\(.*\)</keycloak.version>.*:\1:p' ../pom.xml)
SPID_KC_ADMIN_USERNAME := admin
SPID_KC_ADMIN_PASSWORD := admin
NOW := $(shell date +"%Y%m%d_%H%M%S")

.ONESHELL:

# Basic commands

_sleep:
	@sleep 10

build-provider-jar:
	rm -rf ${PWD}/provider/spid-provider.jar
	make -C ${PWD}/.. build
	cp ${PWD}/../target/spid-provider.jar ${PWD}/provider/spid-provider.jar

create-configuration-client-docker-image:
# Cancellazione directory temporanea
	rm -rf ${PWD}/tmp-docker-configuration-client
#Creazione directory temporanea per dowload dei sorgenti
	mkdir ${PWD}/tmp-docker-configuration-client
	cd ${PWD}/tmp-docker-configuration-client
	git clone https://github.com/polifr/keycloak-spid-provider-configuration-client.git
	docker build --tag spidclient:latest-KC ./keycloak-spid-provider-configuration-client
	cd -
# Cancellazione directory temporanea
	rm -rf ${PWD}/tmp-docker-configuration-client

create-self-signed-certificates:
# Key and crt files generation for keycloak
	rm -rf ${PWD}/certificates/keycloak-server.key ${PWD}/certificates/keycloak-server
	openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
		-keyout ${PWD}/certificates/keycloak-server.key \
		-out ${PWD}/certificates/keycloak-server.crt \
		-subj "/C=IT/ST=MI/L=Milan/O=AgID/OU=Keycloak/CN=keycloak" \
		-addext "subjectAltName = DNS:spid-keycloak, DNS:spid-keycloak:8443, DNS:localhost:8443"
# Key and crt files generation for nginx
	rm -rf ${PWD}/certificates/nginx.key ${PWD}/certificates/nginx.crt
	openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
		-keyout ${PWD}/certificates/nginx.key \
		-out ${PWD}/certificates/nginx.crt \
		-subj "/C=IT/ST=MI/L=Milan/O=AgID/OU=Servizio Accreditamento/CN=spid-nginx" \
		-addext "subjectAltName = DNS:spid-nginx, DNS:spid-nginx:443, DNS:localhost:443"

create-spid-sp-test-docker-image:
# Cancellazione directory temporanea
	rm -rf ${PWD}/tmp-docker-spid-sp-test

#Creazione directory temporanea per dowload dei sorgenti
	mkdir ${PWD}/tmp-docker-spid-sp-test
	cd ${PWD}/tmp-docker-spid-sp-test

	git clone -b fixes-2025 https://github.com/nicolabeghin/spid-sp-test.git

	sed -i "s#<ds:X509Certificate />#<ds:X509Certificate>$$(grep -v CERTIFICATE ./spid-sp-test/src/spid_sp_test/responses/certificates/test_public.cert | tr -d '\n')</ds:X509Certificate>#" \
		./spid-sp-test/src/spid_sp_test/responses/settings.py

	docker build --tag italia/spid-sp-test:0.9.0-KC ./spid-sp-test

	cd -

# Cancellazione directory temporanea
	rm -rf ${PWD}/tmp-docker-spid-sp-test

create-spid-sp-test-metadata-certificates:
# Creazione certificati idp aggiornati
	rm -rf ${PWD}/certificates/spid-sp-test-idp
	mkdir -p ${PWD}/certificates/spid-sp-test-idp

	docker run --net=host --rm \
		-v ${PWD}/certificates/spid-sp-test-idp:/spid \
		--entrypoint "spid-compliant-certificates" -t italia/spid-sp-test:0.9.0-KC generator \
		--key-size 3072 --common-name "agid.gov.it" --days 7650 --entity-id https://localhost:8443 \
		--locality-name Roma --org-id "PA:IT-c_h501" --org-name "AgID TEST" --sector public	

	mv ${PWD}/certificates/spid-sp-test-idp/crt.pem ${PWD}/certificates/spid-sp-test-idp/public.cert
	mv ${PWD}/certificates/spid-sp-test-idp/key.pem ${PWD}/certificates/spid-sp-test-idp/private.key

# Creazione metadata
	rm -rf ${PWD}/tests/spid-sp-test.xml

# spid-sp-test.xml medadata file generation
	docker run --net=host --rm -t \
		-e IDP_CERT_PATH=/spid/ipd-certs \
		-v "${PWD}/certificates/spid-sp-test-idp:/spid/ipd-certs" \
		italia/spid-sp-test:0.9.0-KC --idp-metadata \
		| sed '/^[[:space:]]*</!d' \
		| sed 's/WantAuthnRequestsSigned="false"/WantAuthnRequestsSigned="true" WantAssertionsSigned="false"/' \
		> ${PWD}/tests/spid-sp-test.xml


run-configuration-client:
	rm -rf ${PWD}/configuration-client/log
	mkdir -p ${PWD}/configuration-client/log
	docker run \
		--user "$(id -u):$(id -g)" \
		-v "${PWD}/configuration-client:/opt/mount:rw" \
		--rm \
		--entrypoint cp spidclient:latest-KC /usr/src/app/.env-example /opt/mount/.env-example
	cat ${PWD}/configuration-client/.env-example \
		| sed 's,createSpidSpTestIdP = false,createSpidSpTestIdP = true,g' \
		| sed 's,https://yourdomain.com/spid-sp-test.xml,https://spid-nginx:443/spid-sp-test.xml,g' \
		> ${PWD}/configuration-client/.env
	docker run \
		--net=host \
		-w /usr/src/app \
		-ti --rm \
		-v "${PWD}/configuration-client/.env:/usr/src/app/.env:ro" \
		-v "${PWD}/configuration-client/log:/usr/src/app/log:rw" \
		spidclient:latest-KC


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

init: create-configuration-client-docker-image create-self-signed-certificates create-spid-sp-test-docker-image create-spid-sp-test-metadata-certificates



# Mariadb commands

compose-mariadb:
	SPID_KC_DB_TYPE=mariadb docker compose \
		-f docker-compose-networks.yaml \
		-f docker-compose-mariadb.yaml \
		-f docker-compose-keycloak.yaml \
		-f docker-compose-nginx.yaml \
		up -d --wait

reset-mariadb:
	SPID_KC_DB_TYPE=mariadb docker compose \
		-f docker-compose-networks.yaml \
		-f docker-compose-mariadb.yaml \
		-f docker-compose-keycloak.yaml \
		-f docker-compose-nginx.yaml \
		down -v

setup-mariadb: clean init build-provider-jar compose-mariadb _sleep run-configuration-client

refresh-mariadb: reset-mariadb build-provider-jar compose-mariadb _sleep run-configuration-client

test-mariadb: refresh-mariadb test-responses

full-mariadb: setup-mariadb test-responses



# Mysql commands

compose-mysql:
	SPID_KC_DB_TYPE=mysql docker compose \
		-f docker-compose-networks.yaml \
		-f docker-compose-mysql.yaml \
		-f docker-compose-keycloak.yaml \
		-f docker-compose-nginx.yaml \
		up -d --wait

reset-mysql:
	SPID_KC_DB_TYPE=mysql docker compose \
		-f docker-compose-networks.yaml \
		-f docker-compose-mysql.yaml \
		-f docker-compose-keycloak.yaml \
		-f docker-compose-nginx.yaml \
		down -v

setup-mysql: clean init build-provider-jar compose-mysql _sleep run-configuration-client

refresh-mysql: reset-mysql build-provider-jar compose-mysql _sleep run-configuration-client

test-mysql: refresh-mysql test-responses

full-mysql: setup-mysql test-responses



# Postgres commands

compose-postgres:
	SPID_KC_DB_TYPE=postgres docker compose \
		-f docker-compose-networks.yaml \
		-f docker-compose-postgres.yaml \
		-f docker-compose-keycloak.yaml \
		-f docker-compose-nginx.yaml \
		up -d --wait

reset-postgres:
	SPID_KC_DB_TYPE=postgres docker compose \
		-f docker-compose-networks.yaml \
		-f docker-compose-postgres.yaml \
		-f docker-compose-keycloak.yaml \
		-f docker-compose-nginx.yaml \
		down -v

setup-postgres: clean init build-provider-jar compose-postgres _sleep run-configuration-client

refresh-postgres: reset-postgres build-provider-jar compose-postgres _sleep run-configuration-client

test-postgres: refresh-postgres test-responses

full-postgres: setup-postgres test-responses
