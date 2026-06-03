#!/bin/sh

# Creazione certificati idp aggiornati
rm -rf $(pwd)/certificates/spid-sp-test-idp
mkdir -p $(pwd)/certificates/spid-sp-test-idp

docker run --net=host --rm \
  -v $(pwd)/certificates/spid-sp-test-idp:/spid \
  --entrypoint "spid-compliant-certificates" -t italia/spid-sp-test:0.9.0-KC generator \
  --key-size 3072 --common-name "agid.gov.it" --days 7650 --entity-id https://localhost:8443 \
  --locality-name Roma --org-id "PA:IT-c_h501" --org-name "AgID TEST" --sector public	

mv $(pwd)/certificates/spid-sp-test-idp/crt.pem $(pwd)/certificates/spid-sp-test-idp/public.cert
mv $(pwd)/certificates/spid-sp-test-idp/key.pem $(pwd)/certificates/spid-sp-test-idp/private.key

# Creazione metadata
rm -rf $(pwd)/tests/spid-sp-test.xml

# spid-sp-test.xml medadata file generation
docker run --net=host --rm -t \
  -e IDP_CERT_PATH=/spid/ipd-certs \
  -v "$(pwd)/certificates/spid-sp-test-idp:/spid/ipd-certs" \
  italia/spid-sp-test:0.9.0-KC --idp-metadata \
  | sed '/^[[:space:]]*</!d' \
  | sed 's/WantAuthnRequestsSigned="false"/WantAuthnRequestsSigned="true" WantAssertionsSigned="false"/' \
  > $(pwd)/tests/spid-sp-test.xml

