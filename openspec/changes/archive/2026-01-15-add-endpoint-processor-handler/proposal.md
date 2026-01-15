# Change: Add handler/renderer for HTTP endpoints

## Why
The codebase needs a consistent pattern for HTTP endpoints that separates request handling from response rendering. Today, handlers tend to mix transport concerns (http.ResponseWriter) with domain or view logic, making it harder to test, to reuse rendering logic, and to support multiple output formats (e.g., JSON vs HTML templates).

## What Changes
- Introduce a handler/renderer pattern for HTTP endpoints (an `http.Handler` adapter that invokes an `EndpointFunc` and a `Renderer`).
- Define two distinct response stages:
	- **Processors** which run *before* a response is rendered.
	- **Renderers** which are responsible for writing the response.
- Processors enable middleware-style concerns (sessions, auth, headers, etc.) to compose cleanly.
- Processors MUST NOT call `WriteHeader` or write to the response body.
- The renderer MUST call `WriteHeader` (directly, or indirectly by writing the body).
- Extend the response writer abstraction used by renderers to support explicit cookie changes via a new cookie method.
- Enable renderers to run out-of-process (e.g., for isolating an untrusted renderer) by constraining the parameters passed down the render chain to be serialisable.

## Impact
- Affected specs: http-endpoint (new requirement for handler/renderer abstraction).
- Affected code: HTTP routing / handler wiring code where new endpoints are added.
- No immediate breaking change is required; existing handlers can continue to function until explicitly migrated.
