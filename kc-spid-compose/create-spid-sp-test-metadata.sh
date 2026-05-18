#!/bin/sh

docker pull ghcr.io/italia/spid-sp-test:latest

rm -rf $PWD/tests/spid-sp-test.xml

# Key and crt files generation
docker run --rm -it ghcr.io/italia/spid-sp-test --idp-metadata > $PWD/tests/spid-sp-test.xml
