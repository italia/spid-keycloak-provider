# Configuration Client
It allows the configuration of a keycloak instance with the plugin already installed 

## requirements
* node
* npm

## Configuration
```
npm install
```

copy .env-example into .env, configure it and wipe out the comments

use:
```
npm run create-realm 
```
builds a pre configured realm (with the right Authenticator)

```
npm run create-ips
```
downloads the metadata from the Official Url and build all the spid identity providers in keycloak. It creates also all the suggested mappers (see the main wiki).

If you have a spid test ip (https://github.com/italia/spid-testenv2) deployed somewhere, you can enable the configuration of the keycloak identity provider, setting the following .env file properties

```
createSpidTestIp = true 
spidTestIpAlias = spid-testenv2
spidTestIpMetadataURL = http://localhost:8088/metadata
```


This project is released under the Apache License 2.0, same as the main Keycloak
package.
