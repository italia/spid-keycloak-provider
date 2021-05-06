#!/bin/bash

export JAVA_HOME=/Library/Java/JavaVirtualMachines/liberica-jdk-11.0.2/Contents/Home/

mvn package
cp target/spid-provider.jar ~/keycloak-sia/deployments/spid-provider.jar
docker cp target/spid-provider.jar $(docker ps -q --filter 'name=keycloak'):/opt/jboss/keycloak/standalone/deployments/