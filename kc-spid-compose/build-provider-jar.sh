#!/bin/sh

rm -rf $PWD/provider/spid-provider.jar

docker pull maven:3-eclipse-temurin-17

docker run -it --rm \
  -v $PWD/..:/opt/maven \
  -v $HOME/.m2:/opt/maven-repo/.m2 \
  -w /opt/maven maven:3-eclipse-temurin-17 mvn \
  -Duser.home=/opt/maven-repo \
  -Dmaven.test.skip=true \
  -Ddependency-check.skip=true \
  clean install

cp $PWD/../target/spid-provider.jar $PWD/provider/spid-provider.jar
