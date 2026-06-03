#!/bin/sh

NOW=$(date +"%Y%m%d_%H%M%S")

mkdir -p $(pwd)/tests/report/${NOW}_responses

mkdir -p $(pwd)/tests/dumps/${NOW}_responses

docker run -ti --net=host --rm \
  -e IDP_CERT_PATH=/spid/ipd-certs \
  -v "$(pwd)/certificates/spid-sp-test-idp:/spid/ipd-certs" \
  -v "$(pwd)/tests/report/${NOW}_responses:/spid/html_report:rw" \
  -v "$(pwd)/tests/dumps/${NOW}_responses:/spid/dumps:rw" \
  italia/spid-sp-test:0.9.0-KC \
  --metadata-url "https://localhost:8443/auth/realms/spid/spid-sp-metadata" \
  --authn-url "https://localhost:8443/auth/realms/spid/protocol/openid-connect/auth?client_id=account&scope=openid&response_type=code&redirect_uri=https://localhost:8443/auth/realms/spid/account&state=12345&kc_idp_hint=spid-spid-sp-test" \
  --extra --report_format html --report-output-file html_report/ \
  --test-response --response-html-dumps dumps/
