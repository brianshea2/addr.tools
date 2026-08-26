# Security checklist

Use this checklist for every endpoint or frontend service change.

## Input and upstream requests

- [ ] Bound input length.
- [ ] Reject CR/LF and path injection characters.
- [ ] Validate IP, CIDR, hostname, and record type values.
- [ ] Use request-scoped deadlines.
- [ ] Bound response sizes and concurrency.
- [ ] Avoid unrestricted user-controlled outbound URLs.

## HTTP responses

- [ ] Set an appropriate Content-Type.
- [ ] Avoid stack traces and upstream response bodies in public errors.
- [ ] Apply security headers compatible with the feature.
- [ ] Set cache behaviour intentionally.
- [ ] Set method handling explicitly.

## Privacy

- [ ] Do not add third-party analytics by default.
- [ ] Avoid logging complete sensitive lookup values.
- [ ] Redact credentials, cookies, and tokens.
- [ ] Document external services receiving queries.
- [ ] Document retention and cache behaviour.

## Deployment

- [ ] Check Nginx routing and proxy headers.
- [ ] Check WebSocket, WebRTC, and HTTP/3/QUIC behaviour.
- [ ] Run unit and integration tests.
- [ ] Check container permissions and health checks.
- [ ] Review dependency and image updates.
