[![Build Status](https://travis-ci.com/nicolabeghin/keycloak-spid-provider.svg?branch=master)](https://travis-ci.com/nicolabeghin/keycloak-spid-provider) 
[![GitHub issues](https://img.shields.io/github/issues/nicolabeghin/keycloak-spid-provider)](https://github.com/nicolabeghin/keycloak-spid-provider/issues)

# keycloak-spid-provider
Italian SPID authentication provider for Keycloak (https://www.keycloak.org/)

## Project details
This custom authentication provider for Keycloak enables easy integration of SPID 
with existing applications by leveraging Keycloak identity brokering features.
Keycloak is a nice product, but still lacking on some aspects of SAML2 compatibility,
and the SPID specifications deviate from the SAML2 standard in some key aspects.

Besides the SPID-SAML2 protocol differences, the main issue that this project works around 
is Keycloak's lack of support for transient identities. Also, some of the SP behaviors 
are hardcoded to work with simple IdPs only (i.e. the SP metadata generation is 
severely lacking). Keycloak is slowly improving on this aspect, so over time this plugin 
will become simpler and targeted on implementing only the specific changes required by SPID.

I have documented a reference configuration for SPID and the workarounds required 
in the project wiki (https://github.com/lscorcia/keycloak-spid-provider/wiki). Please make 
sure to read it and understand the config steps and the open issues and
limitations before planning your Production environment.

## Status
This project is still at an alpha stage. It is currently under development 
and things may change quickly. It builds and successfully allows login/logout 
to the SPID-TestEnv2 test IdP (https://github.com/italia/spid-testenv2) 
and to the online SPID tester (https://idptest.spid.gov.it).  
As far as I know it has not been used in Production in any environment yet.  

Until the project gets to a stable release, it will be targeting the most recent release 
of Keycloak as published on the website (see property `version.keycloak` in file `pom.xml`).
Currently the main branch is targeting Keycloak 12.0.0. **Do not use this provider with previous 
versions of Keycloak, it won't work!**  

If you are evaluating this solution, my suggestion is to test the provider by compiling Keycloak
yourself using the latest available sources. Detailed instructions are
available in the project wiki (https://github.com/lscorcia/keycloak-spid-provider/wiki/Installing-the-SPID-provider).

## Build requirements
* git
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

If successful you will find a new provider type called `SPID` in the
`Add Provider` drop down list in the Identity Provider configuration screen.

## Open issues and limitations
Please read the appropriate page on the project wiki 
(https://github.com/lscorcia/keycloak-spid-provider/wiki/Open-issues-and-limitations). 
If your problem is not mentioned there, feel free to open an issue on GitHub.

## Acknowledgements
The basic idea behind this project came from the experimental SPID integration
for older Keycloak versions developed by redhat-italy at 
https://github.com/redhat-italy/keycloak-spid-provider.  

This project is released under the Apache License 2.0, same as the main Keycloak
package.
