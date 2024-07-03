[![Java CI with Maven](https://github.com/italia/keycloak-spid-provider/actions/workflows/maven.yml/badge.svg)](https://github.com/italia/keycloak-spid-provider/actions/workflows/maven.yml)
[![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/italia/keycloak-spid-provider?sort=semver)](https://img.shields.io/github/v/release/italia/keycloak-spid-provider?sort=semver) 
[![GitHub All Releases](https://img.shields.io/github/downloads/italia/keycloak-spid-provider/total)](https://img.shields.io/github/downloads/italia/keycloak-spid-provider/total)
[![GitHub issues](https://img.shields.io/github/issues/italia/keycloak-spid-provider)](https://github.com/italia/keycloak-spid-provider/issues)

# spid-keycloak-provider
Italian SPID authentication provider for Keycloak (https://www.keycloak.org/)

## Project details
This custom authentication provider for Keycloak enables easy integration of SPID 
with existing applications by leveraging Keycloak identity brokering features.
Keycloak is a nice product, but still lacking on some aspects of SAML2 compatibility,
and the SPID specifications deviate from the SAML2 standard in some key aspects.

Besides the SPID-SAML2 protocol differences, some of the SP behaviors
are hardcoded to work with simple IdPs only (i.e. there is no support for generating SP metadata
that joins multiple SPs) . Keycloak is slowly improving on this aspect, so over time this plugin
will become simpler and targeted on implementing only the specific changes required by SPID.

I have documented a reference configuration for SPID and the workarounds required 
in the project wiki (https://github.com/italia/spid-keycloak-provider/wiki). Please make 
sure to read it and understand the config steps and the open issues and
limitations before planning your Production environment.

## Status
This project is still at a development stage but it has been successfully tested for SPID validation and 
**it's currently used in Production**.

Until the project gets to a stable release, it will be targeting the most recent release 
of Keycloak as published on the website (see property `version.keycloak` in file `pom.xml`).
**Do not use the latest release with previous versions of Keycloak, it won't work!**  

Since this plugin uses some Keycloak internal modules, versions of this plugin
are coupled to Keycloak versions. After (major) Keycloak upgrades, you will almost
certainly have also to update this provider.  

## Compatibility
* Keycloak 25.x.x: Release `25.0.1`
* Keycloak 24.x.x: Release `24.0.1`
* Keycloak 23.x.x: Release `1.0.17`
* Keycloak 19.x.x: Release `1.0.16`

## Configuration
### Release 25.0.1 (latest, Keycloak 25.0.1 compatibility)
Detailed instructions on how to install and configure this component are 
available in the project wiki (https://github.com/italia/spid-keycloak-provider/wiki/Installing-the-SPID-provider).
To avoid errors, it's suggested to use anyway https://github.com/nicolabeghin/keycloak-spid-provider-configuration-client

### Release 24.0.1 (latest, Keycloak 24.0.1 compatibility)
With this release targeting latest Keycloak 24.0.1 it was restored the possibility of configuring the plugin through 
the Keycloak web UI, detailed instructions on how to install and configure this component are 
available in the project wiki (https://github.com/italia/spid-keycloak-provider/wiki/Installing-the-SPID-provider).
To avoid errors, it's suggested to use anyway https://github.com/nicolabeghin/keycloak-spid-provider-configuration-client
#### IMPORTANT if upgrading from release 1.0.17
Provider ID was changed from `spid` to `spid-saml` in order to account for [hardcoded Keycloak 24.x behavior](https://github.com/keycloak/keycloak/blob/a228b6c7c9ec7a54ee91bb547b42cc4097ae38e2/js/apps/admin-ui/src/identity-providers/add/DetailSettings.tsx#L396). Before upgrading the plugin make sure to run this SQL query against Keycloak database:

    UPDATE IDENTITY_PROVIDER SET PROVIDER_ID="spid-saml" WHERE PROVIDER_ID="spid"

### Release 1.0.17 (Keycloak 23.x.x compatibility)
With the latest release targeting Keycloak 23.x.x it's not possible to configure the plugin through the Keycloak web UI, 
but only through REST services. Suggested to use https://github.com/nicolabeghin/keycloak-spid-provider-configuration-client

### Release 1.0.6
It's possible to configure the plugin through the Keycloak web UI, detailed instructions
on how to install and configure this component are
available in the project wiki (https://github.com/italia/spid-keycloak-provider/wiki/Installing-the-SPID-provider).
To avoid errors, it's suggested to use anyway https://github.com/nicolabeghin/keycloak-spid-provider-configuration-client

## Build (without docker)
Requirements:
* git
* JDK17+
* Maven

Just run:
```
git clone https://github.com/italia/spid-keycloak-provider.git
cd spid-keycloak-provider
mvn clean package
```
The output package will be generated under `target/spid-provider.jar`.

## Build (with docker)
Requirements:
* Docker

Just run:
```
git clone https://github.com/italia/spid-keycloak-provider.git
cd spid-keycloak-provider
docker run --rm -v $(pwd):/opt/spid-keycloak-provider -w /opt/spid-keycloak-provider maven:3.8.6-openjdk-18-slim bash -c "mvn clean package"
```
The output package will be generated under `target/spid-provider.jar`.

## Deployment
This provider should be deployed as a module, i.e. copied under
`{$KEYCLOAK_PATH}/providers/`, with the right permissions.
Keycloak will take care of loading the module, no restart needed.  

Use this command for reference:  
```
mvn clean package && \
sudo install -C -o keycloak -g keycloak target/spid-provider.jar /opt/keycloak/standalone/deployments/
```

If successful you will find a new provider type called `SPID` in the
`Add Provider` drop down list in the Identity Provider configuration screen.

## Upgrading from previous versions
Upgrades are usually seamless, just repeat the deployment command.  
Then restart Keycloak and it will reload the resources from the packages. Make sure you also clear 
your browser caches or use incognito mode when verifying the correct deployment.
After the first reload you can turn back on the caches and restart Keycloak again.

If you are upgrading to Keycloak v19.x and later, please keep in mind that Keycloak switched the admin console 
to the new "keycloak.v2" theme. This plugin is not yet compatible with the new Admin console theme, 
so you'll have to switch the Admin Console Theme to the older "keycloak" one in order to configure
the SPID-related settings. This issue is tracked at https://github.com/keycloak/keycloak/issues/15344.

## Open issues and limitations
Please read the appropriate page on the project wiki 
(https://github.com/italia/spid-keycloak-provider/wiki/Open-issues-and-limitations). 
If your problem is not mentioned there, feel free to open an issue on GitHub.

## Related projects
If you are interested in Keycloak plugins for the various Italian national auth
systems, you may be interested also in:

* Keycloak SPID Provider - https://github.com/italia/spid-keycloak-provider/  
A Keycloak provider for the SPID federation

* Keycloak CIE ID Provider - https://github.com/lscorcia/keycloak-cieid-provider/  
A Keycloak provider for the CIE ID federation

* Keycloak CNS Authenticator - https://github.com/lscorcia/keycloak-cns-authenticator/  
A Keycloak authenticator to login using CNS tokens and smart cards

## Acknowledgements
The basic idea behind this project came from the experimental SPID integration
for older Keycloak versions developed by redhat-italy at 
https://github.com/redhat-italy/keycloak-spid-provider.  

This project is released under the Apache License 2.0, same as the main Keycloak
package.
