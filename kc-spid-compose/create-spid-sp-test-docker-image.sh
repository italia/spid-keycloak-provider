#!/bin/sh

# Cancellazione directory temporanea
rm -rf $PWD/tmp-docker-spid-sp-test

#Creazione directory temporanea per dowload dei sorgenti
mkdir $PWD/tmp-docker-spid-sp-test
cd $PWD/tmp-docker-spid-sp-test

git clone -b fixes-2025 https://github.com/nicolabeghin/spid-sp-test.git

SPID_SP_TEST_CERTIFICATE=$(cat ./spid-sp-test/src/spid_sp_test/responses/certificates/test_public.cert | grep -v CERTIFICATE | tr -d '\n')
echo SPID_SP_TEST_CERTIFICATE: ${SPID_SP_TEST_CERTIFICATE}
sed -i "s#<ds:X509Certificate />#<ds:X509Certificate>${SPID_SP_TEST_CERTIFICATE}</ds:X509Certificate>#" ./spid-sp-test/src/spid_sp_test/responses/settings.py

docker build --tag italia/spid-sp-test:0.9.0-KC ./spid-sp-test

cd -

# Cancellazione directory temporanea
rm -rf $PWD/tmp-docker-spid-sp-test
