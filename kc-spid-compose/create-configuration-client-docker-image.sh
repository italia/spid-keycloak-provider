#!/bin/sh

# Cancellazione directory temporanea
rm -rf $PWD/tmp-docker-configuration-client

#Creazione directory temporanea per dowload dei sorgenti
mkdir $PWD/tmp-docker-configuration-client
cd $PWD/tmp-docker-configuration-client

git clone https://github.com/polifr/keycloak-spid-provider-configuration-client.git

docker build --tag spidclient:latest-KC ./keycloak-spid-provider-configuration-client

cd -

# Cancellazione directory temporanea
rm -rf $PWD/tmp-docker-configuration-client
