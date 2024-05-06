#!/bin/bash

docker stop addrd
docker rm addrd

docker run --name addrd \
    --restart unless-stopped \
    --network host \
    -v /data:/data \
    -d addrd \
    -c /data/addrd/config.json
