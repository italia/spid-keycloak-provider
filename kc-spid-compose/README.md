# Keycloak SPID Docker Compose

Docker compose for local development and test of Keycloak SPID Provider.

## Initialization
Launch `./create-self-signed-certificates.sh` to create in `certificates`
directory the `keycloak-server.crt.pem` and `keycloak-server.key.pem` files
for running Keycloak with https. This can be launched the first time, you are configuring
the infrastructure, then you can keep the generated files.

In the `certificates` directory there is also the `spid-saml-check.crt` file borrowed
from `spid-saml-check/src/config-sample` project.

Launch `./build-provider-jar.sh` to create the `spid-provider.jar` in the `provider`
directory. Every time you have to update the provider because of changes in the java sources,
you have to launch this script.

All these files are mounted as read only volumes into the Keycloak container, described
into `docker-compose-keycloak.yaml`.

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
Use the [keycloak-spid-provider-configuration-client](https://github.com/nicolabeghin/keycloak-spid-provider-configuration-client)
project to configure the IdP in the Keycloak instance. You can use the `.env` file stored in the
`configuration-client` subdirectory.
**Note**: because of (possible) recent changes in naming specifications, the "First broker login (SPID)"
description is no more accepted in Keycloak (parenthesis are no more allowed).

## Testing
TBD

## Reset compose
To reset the compose infrastructure (i.e. `docker compose down` of all services, volumes and network),
run the `./reset-[database]-compose.sh` script.
