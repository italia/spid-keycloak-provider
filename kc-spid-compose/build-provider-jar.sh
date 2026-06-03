#!/bin/sh

rm -rf $PWD/provider/spid-provider.jar

make -C $PWD/.. build

cp $PWD/../target/spid-provider.jar $PWD/provider/spid-provider.jar
