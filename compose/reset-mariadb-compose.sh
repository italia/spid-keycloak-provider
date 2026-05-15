#!/bin/sh

docker compose -f docker-compose-mariadb.yaml down

rm ./mariadb-volume -rf
