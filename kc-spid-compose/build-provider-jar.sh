#!/bin/sh

JAVA_RELEASE=17

rm -rf $PWD/provider/spid-provider.jar

docker pull maven:3-eclipse-temurin-$JAVA_RELEASE

docker run -it --rm \
  -v $PWD/..:/opt/maven \
  -v $HOME/.m2:/opt/maven-repo/.m2 \
  -w /opt/maven maven:3-eclipse-temurin-$JAVA_RELEASE mvn \
  -Duser.home=/opt/maven-repo \
  -Dmaven.test.skip=true \
  -Ddependency-check.skip=true \
  -Dmaven.compiler.release=$JAVA_RELEASE \
  clean install

cp $PWD/../target/spid-provider.jar $PWD/provider/spid-provider.jar
