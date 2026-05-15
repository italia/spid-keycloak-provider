#!/bin/sh

docker compose -f docker-compose-mysql.yaml down

rm ./mysql-volume -rf
