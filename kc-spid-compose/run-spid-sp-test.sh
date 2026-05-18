#!/bin/sh

docker pull ghcr.io/italia/spid-sp-test:latest

docker run -ti --rm \
  -v "$(pwd)/tests/metadata:/spid/mymetadata:ro" \
  -v "$(pwd)/tests/dumps:/spid/dumps:rw" \
  ghcr.io/italia/spid-sp-test:latest --metadata-url https://localhost:8443/auth/realms/spid/broker/spid-saml/endpoint/spid-keycloak-other.xml
