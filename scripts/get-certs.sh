#!/bin/bash

read -p "Secret: " SECRET
CERTBOT="docker run --rm -it -v /data/letsencrypt:/etc/letsencrypt certbot/certbot"
AUTHHOOK="wget -q -O - \"https://challenges.addr.tools/?secret=$SECRET&txt=\$CERTBOT_VALIDATION\""

$CERTBOT certonly                                                                                            \
  --cert-name dns                                                                                            \
  --manual                                                                                                   \
  --manual-auth-hook "$AUTHHOOK"                                                                             \
  --preferred-challenges dns                                                                                 \
  -d addr.tools                                                                                              \
  -d dnscheck.tools     -d ipv4.dnscheck.tools  -d ipv6.dnscheck.tools                                       \
  -d dns.myaddr.tools   -d dns.myaddr.dev       -d dns.myaddr.io

$CERTBOT certonly                                                                                            \
  --cert-name www                                                                                            \
  --manual                                                                                                   \
  --manual-auth-hook "$AUTHHOOK"                                                                             \
  --preferred-challenges dns                                                                                 \
  -d addr.tools                 -d www.addr.tools                                                            \
  -d challenges.addr.tools                                                                                   \
  -d dnscheck.tools             -d www.dnscheck.tools                                                        \
  -d dyn.addr.tools             -d ipv4.dyn.addr.tools      -d ipv6.dyn.addr.tools                           \
  -d header-echo.addr.tools     -d '*.header-echo.addr.tools'                                                \
  -d info.addr.tools                                                                                         \
  -d ip.addr.tools                                                                                           \
  -d myaddr.tools               -d www.myaddr.tools         -d ipv4.myaddr.tools    -d ipv6.myaddr.tools     \
  -d myaddr.dev                 -d www.myaddr.dev           -d ipv4.myaddr.dev      -d ipv6.myaddr.dev       \
  -d myaddr.io                  -d www.myaddr.io            -d ipv4.myaddr.io       -d ipv6.myaddr.io        \
  -d myip.addr.tools

$CERTBOT certonly                                                                                            \
  --cert-name www-go                                                                                         \
  --manual                                                                                                   \
  --manual-auth-hook "$AUTHHOOK"                                                                             \
  --preferred-challenges dns                                                                                 \
  -d go.dnscheck.tools                  -d '*.go.dnscheck.tools'                                             \
  -d go-ipv4.dnscheck.tools             -d '*.go-ipv4.dnscheck.tools'                                        \
  -d go-ipv6.dnscheck.tools             -d '*.go-ipv6.dnscheck.tools'                                        \
  -d go-alg13.dnscheck.tools            -d '*.go-alg13.dnscheck.tools'                                       \
  -d go-alg13-ipv4.dnscheck.tools       -d '*.go-alg13-ipv4.dnscheck.tools'                                  \
  -d go-alg13-ipv6.dnscheck.tools       -d '*.go-alg13-ipv6.dnscheck.tools'                                  \
  -d go-alg14.dnscheck.tools            -d '*.go-alg14.dnscheck.tools'                                       \
  -d go-alg14-ipv4.dnscheck.tools       -d '*.go-alg14-ipv4.dnscheck.tools'                                  \
  -d go-alg14-ipv6.dnscheck.tools       -d '*.go-alg14-ipv6.dnscheck.tools'                                  \
  -d go-alg15.dnscheck.tools            -d '*.go-alg15.dnscheck.tools'                                       \
  -d go-alg15-ipv4.dnscheck.tools       -d '*.go-alg15-ipv4.dnscheck.tools'                                  \
  -d go-alg15-ipv6.dnscheck.tools       -d '*.go-alg15-ipv6.dnscheck.tools'                                  \
  -d go-unsigned.dnscheck.tools         -d '*.go-unsigned.dnscheck.tools'                                    \
  -d go-unsigned-ipv4.dnscheck.tools    -d '*.go-unsigned-ipv4.dnscheck.tools'                               \
  -d go-unsigned-ipv6.dnscheck.tools    -d '*.go-unsigned-ipv6.dnscheck.tools'

$CERTBOT certonly                                                                                            \
  --cert-name www-ipv4                                                                                       \
  --manual                                                                                                   \
  --manual-auth-hook "$AUTHHOOK"                                                                             \
  --preferred-challenges dns                                                                                 \
  -d myipv4.addr.tools                                                                                       \
  -d self.ip.addr.tools

$CERTBOT certonly                                                                                            \
  --cert-name www-ipv6                                                                                       \
  --manual                                                                                                   \
  --manual-auth-hook "$AUTHHOOK"                                                                             \
  --preferred-challenges dns                                                                                 \
  -d myipv6.addr.tools                                                                                       \
  -d self6.ip.addr.tools
