#!/bin/bash

docker build \
    --no-cache \
    --pull \
    -f "$(dirname "$0")/../Dockerfile.addrd" \
    -t addrd \
    "$(dirname "$0")/.."
