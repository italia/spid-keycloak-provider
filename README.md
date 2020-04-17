[![Build Status](https://travis-ci.com/lscorcia/keycloak-spid-provider.svg?branch=master)](https://travis-ci.com/lscorcia/keycloak-spid-provider) 
[![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/lscorcia/keycloak-spid-provider?sort=semver)](https://img.shields.io/github/v/release/lscorcia/keycloak-spid-provider?sort=semver) 
[![GitHub All Releases](https://img.shields.io/github/downloads/lscorcia/keycloak-spid-provider/total)](https://img.shields.io/github/downloads/lscorcia/keycloak-spid-provider/total)
[![GitHub issues](https://img.shields.io/github/issues/lscorcia/keycloak-spid-provider)](https://github.com/lscorcia/keycloak-spid-provider/issues)

# keycloak-spid-provider
Italian SPID authentication provider for Keycloak/RHSSO

## Build requirements
* JDK8+
* Maven

## Build
Just run `mvn clean package` for a full rebuild. The output package will
be generated under `target/spid-provider.jar`.

## Deployment
This provider should be deployed as a module, i.e. copied under
`{$KEYCLOAK_PATH}/standalone/deployments/`, with the right permissions.
Keycloak will take care of loading the module, no restart needed.  

Use this command for reference:  
```
mvn clean package && \
sudo install -C -o keycloak -g keycloak target/spid-provider.jar /opt/keycloak/standalone/deployments/
```
