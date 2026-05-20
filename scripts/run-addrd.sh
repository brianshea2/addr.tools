#!/bin/bash

docker stop addrd
docker rm addrd

docker run --name addrd \
    --restart unless-stopped \
    --network host \
    -v /data/addrd:/data/addrd \
    -v /data/letsencrypt:/data/letsencrypt:ro \
    -v /data/valkey/run:/data/valkey/run:ro \
    -d addrd \
    -c /data/addrd/config.json
