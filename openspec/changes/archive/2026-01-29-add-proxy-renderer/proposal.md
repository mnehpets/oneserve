## Why

HTTP endpoints sometimes need to forward incoming requests to another HTTP service (internal or external) while preserving method, path, query, body, and most headers. Today, oneserve has renderers for local content (JSON, templates, files), but no first-class renderer for proxying, so proxy behavior is reimplemented ad-hoc in handlers and risks subtle header and streaming bugs.

## What Changes

- Add a new `ProxyRenderer` to the `endpoint` package for `http-endpoint` handlers.
- `ProxyRenderer` will use Go’s standard library reverse proxy implementation to forward the request to a configured upstream endpoint.
- Proxying will preserve request/response bodies and most headers, while ensuring hop-by-hop and proxy-related headers are handled correctly per HTTP semantics.
- Add unit tests and examples demonstrating proxying usage in an endpoint.
- Update documentation to include `ProxyRenderer` alongside existing renderers.

## Capabilities

### New Capabilities
- `proxy-renderer`: A renderer that forwards an incoming HTTP request to a user-specified upstream endpoint using the standard library reverse proxy behavior.

### Modified Capabilities
<!-- None. This change introduces a new renderer capability without changing the core http-endpoint contract. -->

## Impact

- **Code/APIs**: New exported `ProxyRenderer` in `endpoint` (public API). `http-endpoint` documentation/spec updated.
- **Behavior**: Enables streaming proxy responses (no buffering required) and standardized handling of hop-by-hop headers.
- **Dependencies**: Standard library only (e.g., `net/http/httputil`).
- **Tests**: New tests in `endpoint/` validating header behavior and basic proxy forwarding semantics.
