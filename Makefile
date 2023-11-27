SERVICE_TARGET := spid-keycloak-provider

# all our targets are phony (no files to check).
.PHONY: help package

# suppress makes own output
#.SILENT:

help:
	@echo 'Usage: make [TARGET]                                             '

build: package

extract:
	$(eval DOCKER_CONTAINER := $(shell docker create --name tc ${SERVICE_TARGET}:latest))
	mkdir -p target
	docker cp ${DOCKER_CONTAINER}:/opt/app/target/spid-provider.jar target/
	docker rm tc

package:
	rm -fr target || true
	-docker rm tc
	docker build -t ${SERVICE_TARGET} .
	$(MAKE) extract