# HTTP middleware

The `internal/httputil` package contains reusable middleware for browser and API handlers.

## Available helpers

- `SecurityHeaders` applies conservative browser security headers.
- `RequestID` adds a non-sensitive diagnostic identifier.
- `MaxBody` limits request bodies for endpoints that accept data.
- `Methods` rejects unsupported HTTP methods with a JSON error.
- `HealthHandler` provides a dependency-free liveness response.
- `ReadyHandler` provides a basic readiness response.
- `RequestContext` creates a bounded context for downstream network work.
- `LookupValue` validates IP, CIDR, and hostname input.

## Recommended composition

Compose only the middleware appropriate for each service:

```go
handler := httputil.RequestID(
    httputil.SecurityHeaders(
        httputil.Methods(routes, http.MethodGet),
    ),
)
```

Do not apply a restrictive browser policy to WebSocket, WebRTC, or other specialised endpoints without checking their required permissions and protocols. Reverse proxies may add HSTS, TLS settings, rate limits, and deployment-specific Content Security Policy directives.
