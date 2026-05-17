#!/bin/sh

SPID_KC_DB_TYPE=postgres docker compose \
  -f docker-compose-networks.yaml \
  -f docker-compose-postgres.yaml \
  -f docker-compose-keycloak.yaml \
  up
