#!/bin/sh

# Key and crt files generation for keycloak
rm -rf $PWD/certificates/keycloak-server.key $PWD/certificates/keycloak-server
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout $PWD/certificates/keycloak-server.key \
  -out $PWD/certificates/keycloak-server.crt \
  -subj "/C=IT/ST=MI/L=Milan/O=AgID/OU=Keycloak/CN=keycloak" \
  -addext "subjectAltName = DNS:spid-keycloak, DNS:spid-keycloak:8443, DNS:localhost:8443"

# Key and crt files generation for nginx (ref. nicolabeghin Makefile)
rm -rf $PWD/certificates/nginx.key $PWD/certificates/nginx.crt
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout $PWD/certificates/nginx.key \
  -out $PWD/certificates/nginx.crt \
  -subj "/C=IT/ST=MI/L=Milan/O=AgID/OU=Servizio Accreditamento/CN=spid-nginx" \
  -addext "subjectAltName = DNS:spid-nginx, DNS:spid-nginx:443, DNS:localhost:443"
