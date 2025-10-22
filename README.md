# [addr.tools](https://addr.tools/) - possibly useful tools for the Internet

## This repo contains the source code for:
- [challenges.addr.tools](https://challenges.addr.tools/) - dns-01 ACME challenge helper zone
- [dyn.addr.tools](https://dyn.addr.tools/) - simple dynamic DNS for your own domains, no account required
- [info.addr.tools](https://info.addr.tools/) - explore identifying information for domain names and IP addresses
- [myip.addr.tools](https://myip.addr.tools/help) - get your public IP address
- [dnscheck.tools](https://dnscheck.tools/) - identifies your DNS resolvers, checks DNSSEC validation, and more
- [myaddr.tools](https://myaddr.tools/) - yet another dynamic DNS service, custom names included
- addrd - the custom dns server behind many of the above services

## Repo layout:
```
addr.tools
├── cmd/addrd   - dns server application code (Go)
├── configs     - addrd, nginx, and other sample config files
├── internal    - dns server library code (Go)
│   ├── config     - parses the addrd config json, creates and starts the service listeners
│   ├── dns2json   - a simple http handler that provides dns responses in json
│   ├── dnsutil    - dns server utilities (dnssec, edns0, basic handler, etc.)
│   ├── httputil   - http request utilities
│   ├── status     - dns server status handler
│   ├── ttlstore   - a key-value store with value expiration
│   └── zones      - the specific addr.tools service handlers
├── scripts   - build and other helper scripts
└── website   - website content
```
