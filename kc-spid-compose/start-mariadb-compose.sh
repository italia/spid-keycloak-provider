#!/bin/sh

SPID_KC_DB_TYPE=mariadb docker compose \
  -f docker-compose-networks.yaml \
  -f docker-compose-mariadb.yaml \
  -f docker-compose-keycloak.yaml \
  -f docker-compose-nginx.yaml \
  up
