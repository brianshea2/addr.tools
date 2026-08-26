# Privacy notes

addr.tools handles network-related inputs that may be sensitive. Operators should document what is collected, how long it is retained, and which upstream services receive queries.

## Defaults for this fork

- Do not add advertising, third-party analytics, or tracking pixels.
- Avoid logging complete query values unless operationally necessary.
- Redact credentials, tokens, cookies, and authentication headers.
- Use request-scoped timeouts for DNS, RDAP, TLS, and other upstream calls.
- Return generic public errors instead of internal implementation details.
- Keep browser permissions disabled unless a feature explicitly requires them.

The privacy text describes the intended application behaviour. Operators must also review their Nginx, CDN, container, DNS, and logging configuration before deployment.
