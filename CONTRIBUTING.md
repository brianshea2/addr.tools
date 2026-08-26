# Contributing to addr.tools

Thank you for contributing. This fork focuses on fast, privacy-conscious network diagnostics while preserving compatibility with the existing services.

## Development principles

- Keep the service lightweight and dependency-conscious.
- Preserve existing endpoints unless a change is documented as breaking.
- Treat user-supplied domains, addresses, and query parameters as untrusted input.
- Do not add analytics, tracking, or external assets without documenting the privacy impact.
- Prefer small, focused changes with tests.

## Local checks

Run the following before opening a pull request:

```sh
gofmt -w .
go test ./...
go vet ./...
go test -race ./...
```

## Pull requests

Describe the user-facing effect, implementation details, testing performed, and any deployment or configuration changes. Avoid including real user IP addresses, private domains, credentials, or production logs.

## Frontend changes

Keep the frontend accessible, responsive, and usable without JavaScript where practical. Use semantic HTML, visible focus states, keyboard-operable controls, and clear loading and error states.
