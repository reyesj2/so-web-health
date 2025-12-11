#!/bin/bash

docker build -t web-healthagent . && \
docker run --rm -p 8080:8080 --env-file .env web-healthagent
