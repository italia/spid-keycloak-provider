# Keycloak SPID Docker Compose

Docker compose for local development and test of Keycloak SPID Provider.

## Initialization
Launch `./create-self-signed-certificates.sh` to create in `certificates`
directory the `keycloak-server.crt` and `keycloak-server.key` files
for running Keycloak with https, and the `nginx.crt` and `nginx.key` for
https on nginx.
This can be launched the first time, you are configuring
the infrastructure, then you can keep the generated files.

In the `certificates` directory there is also the `spid-saml-check.crt` file borrowed
from `spid-saml-check/src/config-sample` project.

Launch `./build-provider-jar.sh` to create the `spid-provider.jar` in the `provider`
directory. Every time you have to update the provider because of changes in the java sources,
you have to launch this script.

All these files are mounted as read only volumes into the Keycloak container, described
into `docker-compose-keycloak.yaml`.

Because the configuration and the test infrastructure are based on custom branches of
`keycloak-spid-provider-configuration-client` and `spid-sp-test` prijects, you have to
build the custom docker images with the `./create-configuration-client-docker-image.sh`
and `./create-spid-sp-test-docker-image.sh` scripts before the following steps.

Launch `./create-spid-sp-test-metadata.sh` to create the `spid-sp-test.xml` file
that will be used for IdP configuration and for running tests.

## Start compose
To start the compose infrastructure, choose a db type (i.e. `mariadb`, `mysql` or `postgres`)
and launch the corresponding script; this will create the network, volumes, db and Keycloak instances.
Database ports are exposed, so you can access the services using 3306 (for mariadb and mysql) and 5432
(for postgres).
During start, Keycloak will import the `spid-realm.json` from `realm` directory to preconfigure
the environment that is used by `keycloak-spid-provider-configuration-client`.
Common environment variables are set in the `.env` file of the current directory.

## Identity Providers configuration
Launch the `run-configuration-client-docker.sh` script, that will configure all the IdPs in the running
Keycloak instance.
**Note**: because of (possible) recent changes in naming specifications, the "First broker login (SPID)"
description is no more accepted in Keycloak (parenthesis are no more allowed).

## Testing
You can launch the scripts:
- `./run-spid-sp-test-metadata.sh`
- `./run-spid-sp-test-authn.sh`
- `./run-spid-sp-test-responses.sh`
Please refer to `spid-sp-test` project documentation.

## Reset compose
To reset the compose infrastructure (i.e. `docker compose down` of all services, volumes and network),
run the `./reset-[database]-compose.sh` script.
