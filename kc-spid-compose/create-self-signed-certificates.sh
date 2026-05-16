#!/bin/sh

# Key and crt files generation
openssl req -newkey rsa:2048 -nodes \
  -keyout $PWD/certificates/keycloak-server.key.pem -x509 -days 3650 \
  -out $PWD/certificates/keycloak-server.crt.pem

# Keystore generation
openssl pkcs12 -export \
  -in $PWD/certificates/keycloak-server.crt.pem \
  -inkey $PWD/certificates/keycloak-server.key.pem \
  -out $PWD/certificates/keycloak-server.p12
