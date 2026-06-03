#!/bin/sh

NOW=$(date +"%Y%m%d_%H%M%S")

docker run -ti --net=host --rm \
  -v "$(pwd)/tests/report/${NOW}_authn:/spid/html_report:rw" \
  italia/spid-sp-test:0.9.0-KC \
  --metadata-url "https://localhost:8443/auth/realms/spid/spid-sp-metadata" \
  --authn-url "https://localhost:8443/auth/realms/spid/protocol/openid-connect/auth?client_id=account&scope=openid&response_type=code&redirect_uri=https://localhost:8443/auth/realms/spid/account&state=12345&kc_idp_hint=spid-spid-sp-test" \
  --extra --report_format html --report-output-file html_report/
