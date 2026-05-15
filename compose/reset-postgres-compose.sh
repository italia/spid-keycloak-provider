#!/bin/sh

docker compose -f docker-compose-postgres.yaml down

rm ./postgres-volume -rf
