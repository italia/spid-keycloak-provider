#!/bin/sh

rm -rf $PWD/tests/spid-sp-test.xml

# spid-sp-test.xml medadata file generation
docker run --net=host --rm -t italia/spid-sp-test --idp-metadata \
  | sed 's/WantAuthnRequestsSigned="false"/WantAuthnRequestsSigned="true" WantAssertionsSigned="false"/' \
  > $PWD/tests/spid-sp-test.xml
