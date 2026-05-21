#!/bin/sh

rm -rf $PWD/certificates/keycloak-server.key.pem $PWD/certificates/keycloak-server.crt.pem

# Key and crt files generation for keycloak
openssl req -newkey rsa:2048 -nodes \
  -keyout $PWD/certificates/keycloak-server.key.pem -x509 -days 3650 \
  -out $PWD/certificates/keycloak-server.crt.pem

# Key and crt files generation for nginx (ref. nicolabeghin Makefile)
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
		-keyout $PWD/certificates/nginx.key \
		-out $PWD/certificates/nginx.crt \
		-subj "/C=IT/ST=MI/L=Milan/O=AgID/OU=Servizio Accreditamento/CN=nginx" \
		-addext "subjectAltName = DNS:nginx"
