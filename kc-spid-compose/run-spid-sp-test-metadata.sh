#!/bin/sh

docker run --net=host --rm \
  -v "$(pwd)/tests/report:/spid/html_report:rw" \
  -v "$(pwd)/tests/dumps:/spid/dumps:rw" \
  -t italia/spid-sp-test \
  --metadata-url https://localhost:8443/auth/realms/spid/spid-sp-metadata
