#!/bin/bash

echo -n '['
curl -fs 'https://www.cloudflare.com/ips-v4' \
    | jq -Rsj '{desc: "Cloudflare", source: "https://www.cloudflare.com/ips-v4", ranges: split("\n")}'
echo ','
curl -fs 'https://www.cloudflare.com/ips-v6' \
    | jq -Rsj '{desc: "Cloudflare", source: "https://www.cloudflare.com/ips-v6", ranges: split("\n")}'
echo ','
curl -fs 'https://quad9.net/ipranges/quad9-outbound-brief-latest.json' \
    | jq -j '{desc: "Quad9 (partnered with {})", source: "https://quad9.net/ipranges/quad9-outbound-brief-latest.json", ranges: (.ipv4 + .ipv6)}'
echo ']'
