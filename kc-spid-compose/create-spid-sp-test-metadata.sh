#!/bin/sh

docker pull ghcr.io/italia/spid-sp-test:latest

rm -rf $PWD/tests/metadata/spid-sp-test.xml
mkdir -p $PWD/tests/metadata

# Key and crt files generation
docker run --rm -it ghcr.io/italia/spid-sp-test --idp-metadata > $PWD/tests/metadata/spid-sp-test.xml
