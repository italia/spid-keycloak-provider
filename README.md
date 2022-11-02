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
This project is still at an alpha stage. It is currently under development 
and things may change quickly. It builds and successfully allows login/logout 
to the SPID Validator test IdP (https://github.com/italia/spid-saml-check) 
and to the online SPID tester (https://www.spid-validator.it).  
As far as I know it has not been used in Production in any environment yet.  

Until the project gets to a stable release, it will be targeting the most recent release 
of Keycloak as published on the website (see property `version.keycloak` in file `pom.xml`).
Currently the main branch is targeting Keycloak 19.0.3. **Do not use the latest release with previous
versions of Keycloak, it won't work!**  

Since this plugin uses some Keycloak internal modules, versions of this plugin
are coupled to Keycloak versions. After (major) Keycloak upgrades, you will almost
certainly have also to update this provider.  

Detailed instructions on how to install and configure this component are
available in the project wiki (https://github.com/italia/spid-keycloak-provider/wiki/Installing-the-SPID-provider).

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

## Upgrading from previous versions
Upgrades are usually seamless, just repeat the deployment command.  
Sometimes Keycloak caches don't get flushed when a new deployment occurs; in that case you will need
to edit the file `{$KEYCLOAK_PATH}/standalone/configuration/standalone.xml`, find the following section
```
<theme>
  <staticMaxAge>2592000</staticMaxAge>
  <cacheThemes>true</cacheThemes>
  <cacheTemplates>true</cacheTemplates>
  <dir>${jboss.home.dir}/themes</dir>
</theme>
```
and change it to:
```
<theme>
  <staticMaxAge>-1</staticMaxAge>
  <cacheThemes>false</cacheThemes>
  <cacheTemplates>false</cacheTemplates>
  <dir>${jboss.home.dir}/themes</dir>
</theme>
```

Then restart Keycloak and it will reload the resources from the packages. Make sure you also clear 
your browser caches or use incognito mode when verifying the correct deployment.
After the first reload you can turn back on the caches and restart Keycloak again.

If you are upgrading to Keycloak v19.x, please keep in mind that Keycloak switched the admin console 
to the new "keycloak.v2" theme. This plugin is not yet compatible with the new Admin console theme, 
so you'll have to switch the Admin Console Theme to the older "keycloak" one in order to configure
the SPID-related settings.

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
