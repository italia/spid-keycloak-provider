#!/bin/sh

rm -rf $PWD/tests/spid-sp-test.xml

# spid-sp-test.xml medadata file generation
docker run --net=host --rm -t italia/spid-sp-test:0.9.0 --idp-metadata \
  | sed '/^[[:space:]]*</!d' \
  | sed 's/WantAuthnRequestsSigned="false"/WantAuthnRequestsSigned="true" WantAssertionsSigned="false"/' \
  > $PWD/tests/spid-sp-test.xml
