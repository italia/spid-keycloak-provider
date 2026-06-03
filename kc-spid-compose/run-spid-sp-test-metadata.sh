#!/bin/sh

NOW=$(date +"%Y%m%d_%H%M%S")

docker run -ti --net=host --rm \
  -v "$(pwd)/tests/report/${NOW}_metadata:/spid/html_report:rw" \
  italia/spid-sp-test:0.9.0-KC \
  --metadata-url "https://localhost:8443/auth/realms/spid/spid-sp-metadata" \
  --extra --report_format html --report-output-file html_report/
