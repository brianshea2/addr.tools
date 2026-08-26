# API notes

This document records the compatibility expectations for the public HTTP services while the fork is being improved.

## Compatibility

Existing service-specific hosts and paths should remain available unless a change is explicitly marked breaking. New browser experiences should call documented endpoints rather than guessing URL formats.

## Input handling

All query values are untrusted. Handlers should validate and normalise input before DNS, RDAP, TLS, or network operations. Inputs must have bounded length, and upstream operations must use request-scoped contexts and timeouts.

## Errors

JSON endpoints should use the following shape for errors:

```json
{"error":"human-readable message"}
```

Error responses must not expose stack traces, credentials, resolver internals, or upstream response bodies by default.

## Rate limits and caching

Deployments should apply rate limits at the reverse proxy or application layer. Cache lifetimes must respect DNS TTLs and must not cause private query data to be retained longer than documented.
