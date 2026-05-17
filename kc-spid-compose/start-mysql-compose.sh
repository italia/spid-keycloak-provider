#!/bin/sh

SPID_KC_DB_TYPE=mysql docker compose \
  -f docker-compose-networks.yaml \
  -f docker-compose-mysql.yaml \
  -f docker-compose-keycloak.yaml \
  up
