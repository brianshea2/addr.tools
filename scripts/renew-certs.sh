#!/bin/bash

docker run --rm -it -v /data/letsencrypt:/etc/letsencrypt certbot/certbot renew "$@"
