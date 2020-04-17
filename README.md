[![Build Status](https://travis-ci.com/lscorcia/keycloak-spid-provider.svg?branch=master)](https://travis-ci.com/lscorcia/keycloak-spid-provider) 
[![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/lscorcia/keycloak-spid-provider?sort=semver)](https://img.shields.io/github/v/release/lscorcia/keycloak-spid-provider?sort=semver) 
[![GitHub All Releases](https://img.shields.io/github/downloads/lscorcia/keycloak-spid-provider/total)](https://img.shields.io/github/downloads/lscorcia/keycloak-spid-provider/total)
[![GitHub issues](https://img.shields.io/github/issues/lscorcia/keycloak-spid-provider)](https://github.com/lscorcia/keycloak-spid-provider/issues)

# keycloak-spid-provider
Italian SPID authentication provider for Keycloak (https://www.keycloak.org/)

## Project details
This custom authentication provider for Keycloak enables easy integration of SPID 
with existing applications by leveraging Keycloak identity brokering features.
Keycloak is a nice product, but still lacking on some aspects of SAML2 compatibility,
and the SPID specifications deviate from the SAML2 standard in some key aspects.

The main issue to overcome is that Keycloak still does not support transient identities,
and some of the SP behaviors are hardcoded to work with simple IdPs only (i.e. the
SP metadata generation is severely lacking).

I plan to document a reference configuration for SPID and the workarounds required 
in the project wiki (https://github.com/lscorcia/keycloak-spid-provider/wiki).

## Status
This project is still at an alpha stage. It is currently under development 
and things may change quickly.  
Also, as far as I know it has not been used in Production in any environment yet.  

It builds, and successfully allows login to the SPID-TestEnv2 test IdP 
(https://github.com/italia/spid-testenv2). Single Logout isn't fully working yet.

Until the project gets to a stable release, it will be targeting the latest release 
of Keycloak published on the website (see property `version.keycloak` in file `pom.xml`).

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

If everything went fine you will find a new provider type called `SPID` in the
'Add Provider' drop down list in the Identity Provider configuration screen.

## Acknowledgements
The basic idea behind this project came from the experimental SPID integration
for older Keycloak versions developed by redhat-italy at 
https://github.com/redhat-italy/keycloak-spid-provider.  
At the moment the two project still share the same package namespace definitions,
but if it'll ever get to a usable and tested stage I'll take care of clearly
separating the two works.
