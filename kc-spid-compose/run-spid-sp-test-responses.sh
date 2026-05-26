#!/bin/sh

docker run --net=host --rm \
  -v "$(pwd)/tests/report:/spid/html_report:rw" \
  -v "$(pwd)/tests/responses:/spid/responses:rw" \
  -v "$(pwd)/tests/dumps:/spid/dumps:rw" \
  -t italia/spid-sp-test:0.9.0-KC --test-response \
  --metadata-url https://localhost:8443/auth/realms/spid/spid-sp-metadata \
  --authn-url "https://localhost:8443/auth/realms/spid/protocol/openid-connect/auth?client_id=account&scope=openid&response_type=code&redirect_uri=https://localhost:8443/auth/realms/spid/account&state=12345&kc_idp_hint=spid-spid-sp-test"
