# Service routes

This fork contains multiple browser-facing services behind the `addrd` application and the Nginx deployment configuration. Route changes must be checked against both the service directory and the reverse proxy configuration.

## Services

- `addr.tools` — primary landing page and address tools.
- `info.addr.tools` — IP and network information pages.
- `myip.addr.tools` — public address display.
- `myaddr.tools` — address-related service.
- `dyn.addr.tools` — dynamic DNS service.
- `dnscheck.tools` — DNS and TLS diagnostics.
- `challenges.addr.tools` — challenge workflows.

## Frontend lookup links

The primary landing page should link to a route that is confirmed by the information service implementation. Do not infer a route solely from the hostname or directory name. If a route is changed, update the frontend, Nginx configuration, and this document together.

## Specialised protocols

WebSocket, WebRTC/STUN, DNS-over-QUIC, and browser-permission features may require different headers and proxy handling. They should not automatically inherit a restrictive browser policy designed for static HTML pages.

## Change checklist

- Confirm the route in the handler implementation.
- Confirm the route in `configs/nginx-http.conf`.
- Confirm the corresponding website directory and assets.
- Add or update an integration test.
- Verify redirects, canonical URLs, and error pages.
- Check WebSocket and upgraded-connection behaviour where applicable.
