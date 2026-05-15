#!/bin/sh

openssl req -newkey rsa:2048 -nodes \
  -keyout $PWD/certificates/keycloak-server.key.pem -x509 -days 3650 \
  -out $PWD/certificates/keycloak-server.crt.pem
