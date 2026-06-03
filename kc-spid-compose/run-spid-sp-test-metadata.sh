#!/bin/sh

NOW=$(date +"%Y%m%d_%H%M%S")
mkdir -p $(pwd)/tests/report/${NOW}_metadata

docker run -ti --net=host --rm \
  -e IDP_CERT_PATH=/spid/ipd-certs \
  -v "$(pwd)/certificates/spid-sp-test-idp:/spid/ipd-certs" \
  -v "$(pwd)/tests/report/${NOW}_metadata:/spid/html_report:rw" \
  italia/spid-sp-test:0.9.0-KC \
  --metadata-url "https://localhost:8443/auth/realms/spid/spid-sp-metadata" \
  --extra --report_format html --report-output-file html_report/
