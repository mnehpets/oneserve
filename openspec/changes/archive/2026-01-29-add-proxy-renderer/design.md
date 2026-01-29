## Context

The `endpoint` package provides a structured HTTP handler adapter (`EndpointHandler`) that decodes request parameters into a typed `params` value, executes business logic via `EndpointFunc`, and then delegates HTTP response construction to a `Renderer`.

This change adds a `ProxyRenderer` to the `endpoint` package, implemented on top of Go’s standard library reverse proxy support.

## Goals / Non-Goals

**Goals:**
- Provide a small, safe wrapper around `net/http/httputil.ReverseProxy` that fits the `endpoint.Renderer` contract.
- Make proxying usable from an `EndpointFunc` without re-implementing proxy logic in handlers.
- Preserve request/response bodies and non-hop-by-hop headers, while letting the standard library handle hop-by-hop/proxy semantics.
- Support streaming (no mandatory buffering).
- Include tests that validate basic forwarding and header handling.

**Non-Goals:**
- A full API gateway feature set (routing tables, retries, circuit breaking, rate limiting).
- Request/response body transformation.
- Defining or enforcing a bespoke `X-Forwarded-*` policy beyond standard library defaults.

## Decisions

### Use `net/http/httputil.ReverseProxy`
**Decision:** Implement `ProxyRenderer` by wrapping `httputil.ReverseProxy`.

**Rationale:** `ReverseProxy` already implements correct handling for hop-by-hop headers, connection upgrades, streaming bodies, and request/response copying. Reusing it reduces maintenance risk and aligns behavior with widely used Go proxy semantics.

**Alternatives considered:**
- Hand-rolled proxy via `http.Client` and manual header/body copying. Rejected due to correctness pitfalls (hop-by-hop headers, `Trailer`, upgrades, flush behavior).

### Configuration shape (minimal wrapper)
**Decision:** `ProxyRenderer` will be a thin wrapper around a fully-initialized `*httputil.ReverseProxy`. A convenience constructor will be provided for the common case.

Proposed API (exact names to be finalized in implementation/spec):
- `type ProxyRenderer struct {
	Proxy     *httputil.ReverseProxy
	}`

- `func NewProxyRenderer(targetURL string) (*ProxyRenderer, error)` that parses `targetURL` and uses `httputil.NewSingleHostReverseProxy`.

**Rationale:** This keeps the surface area small and makes behavior easy to reason about: `ReverseProxy` is the implementation; `ProxyRenderer` just adapts it to the renderer pattern. `NewProxyRenderer(targetURL)` supports the most common case where the endpoint can compute the upstream URL as a string (e.g., from config and request parameters) and wants a safe, standard default proxy without manually constructing `*url.URL` values.

**Alternatives considered:**
- Adding many configuration knobs on `ProxyRenderer`. Rejected as unnecessary for the initial capability; it can be added later if a spec justifies it.
- Omitting a convenience constructor. Rejected because it makes the common case noisy and encourages ad-hoc proxy construction.

### Header policy
**Decision:** Rely on `httputil.ReverseProxy` behavior for hop-by-hop header removal and proxy semantics, while preserving other headers and streaming bodies.

**Rationale:** `ReverseProxy` removes hop-by-hop headers per RFC 7230 and maintains correctness for upgrade requests. Content headers should be preserved as part of copying behavior.

Implementation notes:
- Prefer `httputil.NewSingleHostReverseProxy` so the standard library owns URL rewriting and header policy.
- Keep request/response mutation in the `ReverseProxy` hooks (`Director`, `Rewrite`, `ModifyResponse`, `ErrorHandler`) when callers need custom behavior.

### Error handling and renderer contract
**Decision:** `ProxyRenderer.Render` is terminal and delegates to `ReverseProxy.ServeHTTP(w, r)`.

**Rationale:** Reverse proxying necessarily writes a complete HTTP response. Upstream failures can occur after bytes have been written; the correct place to handle those is `ReverseProxy.ErrorHandler` (and standard library defaults), not the endpoint error path.

**Alternatives considered:**
- Returning an `endpoint.Error(...)` for upstream failures. Rejected because failures can occur after partial response data has already been sent; standard proxy handling is more appropriate.

## Risks / Trade-offs

- **[Ambiguity: URL/path rewriting expectations]** → Mitigation: specify and test the intended behavior (and align to `NewSingleHostReverseProxy` semantics).
- **[Header correctness differences across Go versions]** → Mitigation: keep to standard library APIs and test against behavior, not internal implementation details.
- **[Streaming semantics hard to test]** → Mitigation: add integration-style unit tests using `httptest.Server` and verify non-buffering by checking chunked transfer / flush behavior where feasible.
- **[Security: open proxy / SSRF risk]** → Mitigation: `ProxyRenderer` requires an explicit configured upstream URL; examples should discourage user-controlled upstream targets unless validated.

