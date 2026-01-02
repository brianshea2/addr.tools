#!/bin/bash

read -p "Secret: " SECRET
CERTBOT="docker run --rm -it -v /data/letsencrypt:/etc/letsencrypt certbot/certbot"
AUTHHOOK="wget -q -O - \"https://challenges.addr.tools/?secret=$SECRET&txt=\$CERTBOT_VALIDATION\""

$CERTBOT certonly                                                                                                       \
  --cert-name dns.addr.tools                                                                                            \
  --manual                                                                                                              \
  --manual-auth-hook "$AUTHHOOK"                                                                                        \
  --preferred-challenges dns                                                                                            \
  -d dns.addr.tools                     -d '*.dns.addr.tools'                                                           \
  -d ns1.myaddr.tools                   -d ns2.myaddr.tools                                                             \
  -d ns1.myaddr.dev                     -d ns2.myaddr.dev                                                               \
  -d ns1.myaddr.io                      -d ns2.myaddr.io

$CERTBOT certonly                                                                                                       \
  --cert-name addr.tools                                                                                                \
  --manual                                                                                                              \
  --manual-auth-hook "$AUTHHOOK"                                                                                        \
  --preferred-challenges dns                                                                                            \
  -d addr.tools                         -d '*.addr.tools'                                                               \
  -d ipv4.dyn.addr.tools                -d ipv6.dyn.addr.tools

$CERTBOT certonly                                                                                                       \
  --cert-name dnscheck.tools                                                                                            \
  --manual                                                                                                              \
  --manual-auth-hook "$AUTHHOOK"                                                                                        \
  --preferred-challenges dns                                                                                            \
  -d dnscheck.tools                     -d '*.dnscheck.tools'                                                           \
  -d '*.test.dnscheck.tools'            -d '*.test-ipv4.dnscheck.tools'         -d '*.test-ipv6.dnscheck.tools'         \
  -d '*.test-alg13.dnscheck.tools'      -d '*.test-alg13-ipv4.dnscheck.tools'   -d '*.test-alg13-ipv6.dnscheck.tools'   \
  -d '*.test-alg14.dnscheck.tools'      -d '*.test-alg14-ipv4.dnscheck.tools'   -d '*.test-alg14-ipv6.dnscheck.tools'   \
  -d '*.test-alg15.dnscheck.tools'      -d '*.test-alg15-ipv4.dnscheck.tools'   -d '*.test-alg15-ipv6.dnscheck.tools'

$CERTBOT certonly                                                                                                       \
  --cert-name myaddr.tools                                                                                              \
  --manual                                                                                                              \
  --manual-auth-hook "$AUTHHOOK"                                                                                        \
  --preferred-challenges dns                                                                                            \
  -d myaddr.tools   -d www.myaddr.tools     -d ipv4.myaddr.tools    -d ipv6.myaddr.tools                                \
  -d myaddr.dev     -d www.myaddr.dev       -d ipv4.myaddr.dev      -d ipv6.myaddr.dev                                  \
  -d myaddr.io      -d www.myaddr.io        -d ipv4.myaddr.io       -d ipv6.myaddr.io
