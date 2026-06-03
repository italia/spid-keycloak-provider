#!/bin/sh

NOW=$(date +"%Y%m%d_%H%M%S")

docker run -ti --net=host --rm \
  -v "$(pwd)/tests/report/${NOW}:/spid/html_report:rw" \
  -v "$(pwd)/tests/dumps/${NOW}:/spid/dumps:rw" \
  italia/spid-sp-test:0.9.0-KC \
  --metadata-url "https://localhost:8443/auth/realms/spid/spid-sp-metadata" \
  --authn-url "https://localhost:8443/auth/realms/spid/protocol/openid-connect/auth?client_id=account&scope=openid&response_type=code&redirect_uri=https://localhost:8443/auth/realms/spid/account&state=12345&kc_idp_hint=spid-spid-sp-test" \
  --test-response \
  --extra -rf html -o html_report/ --response-html-dumps dumps/
