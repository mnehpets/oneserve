## 1. Implementation


- [x] 1.1 Define the `Renderer` + `Processor` interfaces
	- [x] 1.1.1 Define the final `Renderer` protocol:
		- `Render(w http.ResponseWriter, r *http.Request) error`
	- [x] 1.1.2 Define the `Processor` protocol:
		- `Process(w http.ResponseWriter, r *http.Request, next func(w http.ResponseWriter, r *http.Request) error) error`
	- [x] 1.1.3 Define and document policy:
		- A `Processor` MUST NOT call `w.WriteHeader(...)`.
		- A `Processor` MUST NOT write to the response body.
		- A `Renderer` MUST call `w.WriteHeader(...)` (directly or indirectly by writing the body).
	- [x] 1.1.4 Define the processor chain helper that runs processors and then a renderer, ensuring exactly one top-level call.
	- [x] 1.1.5 Define error handling: first non-nil error stops and is returned.

### 1.A Renderer types

- [x] 1.2 Implement plain-text renderer
	- [x] 1.2.1 Implement a `Renderer` that writes a text body and sets `Content-Type` to `text/plain; charset=utf-8` (or project default).
	- [x] 1.2.2 Add tests for status code handling, headers, and body content.

- [x] 1.3 Implement HTML renderer
	- [x] 1.3.1 Implement a `Renderer` that writes HTML and sets `Content-Type` to `text/html; charset=utf-8`.
	- [x] 1.3.2 Add tests for HTML responses and headers.

- [x] 1.4 Implement JSON renderer
	- [x] 1.4.1 Implement a `Renderer` that serializes a value as JSON and sets `Content-Type` to `application/json`.
	- [x] 1.4.2 Define behavior for JSON encoding errors (e.g., fall back to 500 error renderer).
	- [x] 1.4.3 Add tests for successful JSON encoding and error paths.

- [x] 1.5 Implement template-based renderers
	- [x] 1.5.1 Implement a `Renderer` that uses Go `text/template`.
	- [x] 1.5.2 Implement a `Renderer` that uses Go `html/template`.
	- [x] 1.5.3 Add tests for both template engines, including template execution failures.

- [x] 1.6 Implement static file renderer
	- [x] 1.6.1 Implement a `Renderer` that serves a single static file from disk (or configured filesystem).
	- [x] 1.6.2 Set `Content-Type` based on file extension/MIME detection.
	- [x] 1.6.3 Set `Last-Modified` (or equivalent) header from file metadata.
	- [x] 1.6.4 Define behavior when the file does not exist or cannot be read (Renderer indicates appropriate HTTP error per conventions, e.g. 404/500).
	- [x] 1.6.5 Add tests for existing file and missing/unreadable file behavior (status + body/headers as applicable).

- [x] 1.7 Implement static directory renderer
	- [x] 1.7.1 Implement a `Renderer` that lists directory contents.
	- [x] 1.7.2 Support an HTML template for directory listing when configured.
	- [x] 1.7.3 Set a suitable `Content-Type` (e.g., `text/html`).
	- [x] 1.7.4 Add tests for directory listing, and empty directory

- [x] 1.8 Implement common HTTP errors as Go errors
	- [x] 1.8.1 Define an `EndpointError` type that carries:
		- HTTP status code
		- human-readable message
		- optional cause (supports `Unwrap()`)
	- [x] 1.8.2 Update `EndpointHandler` to map `EndpointError` to an HTTP response:
		- status code from `EndpointError.Status`
		- body from `EndpointError.Message` (or `http.StatusText` fallback)
	- [x] 1.8.3 Ensure `EndpointError` can be returned from both:
		- `EndpointFunc` implementations.
		- internally within `EndpointHandler` itself (e.g., parameter decode failures).
	- [x] 1.8.4 Add tests for status mapping behavior.

- [x] 1.9 Test cookie interactions
	- [x] 1.9.1 Implement a cookie-aware response-writer abstraction used by renderers (Implemented via Defer/Commit hooks)
		- [x] 1.9.1.1 Provide an explicit cookie method for setting/updating/clearing cookies.
		- [x] 1.9.1.2 Ensure cookie mutations are applied in addition to headers and body output.
		- [x] 1.9.1.3 Add tests for cookie mutation ordering and composition.
	- [x] 1.9.2 Provide cookie-modifying renderers/helpers that can:
		- Add new cookies.
		- Update existing cookies.
		- Mark cookies for deletion (e.g., via expired `Set-Cookie` headers).
	- [x] 1.9.3 Ensure cookie modifications compose correctly with body rendering and other headers.
	- [x] 1.9.4 Add tests covering all cookie operations and interaction with other renderers.

- [x] 1.10 Implement secure-cookie session middleware (as a processor)
	- [x] 1.10.1 Define session data model and context key (store/retrieve session via `r.Context()`).
	- [x] 1.10.2 Implement secure cookie codec (encrypt+authenticate or equivalent) with key rotation support.
	- [x] 1.10.3 Implement session middleware processor that:
		- Loads session from request cookie; invalid cookie => empty session (optionally clear).
		- Makes session available to downstream renderers and `EndpointFunc`.
		- Persists changes by emitting `Set-Cookie`.
	- [x] 1.10.4 Define cookie attributes defaults (`HttpOnly`, `Secure` over HTTPS, `SameSite`, `Path=/`).
	- [x] 1.10.5 Add tests for decode failure, encode, key rotation, and cookie attribute behavior.

### 1.B `EndpointHandler` and parameter sources

- [x] 1.11 Implement `EndpointHandler` and endpoint function type
	- [x] 1.11.1 Define the endpoint function type `EndpointFunc` with the required signature:
		- `type EndpointFunc[P any] func(w http.ResponseWriter, r *http.Request, params P) (Renderer, error)`
	- [x] 1.11.2 Implement an `EndpointHandler` type that:
		- Wraps a single `EndpointFunc`.
		- Implements `http.Handler`.
		- Invokes the `EndpointFunc` and uses the returned `Renderer` by invoking the processor chain (single top-level call).
	- [x] 1.11.3 Implement error types that allow Renderers and Processors to return specific HTTP status codes

- [x] 1.13 `Unmarshal` decoding: runtime type & tags
	- [x] 1.13.1 Implement logic to inspect the runtime type of `params` (e.g., struct) using reflection.
	- [x] 1.13.2 Define and document struct tag conventions to map fields to parameter sources and names.
	- [x] 1.13.3 Ensure fields without matching data retain their zero value unless overridden by tags.
	- [x] 1.13.4 Expose stdlib-style `Unmarshal(r *http.Request, params any) error` entrypoint
		- [x] 1.13.4.1 Validate `params` is a non-nil pointer to a settable value; otherwise return an error.
		- [x] 1.13.4.2 Ensure `EndpointHandler` uses `Unmarshal(...)` (no separate decoding path).
		- [x] 1.13.4.3 Ensure `Unmarshal(...)` is usable from ordinary `net/http` handlers (`http.Handler` / `http.HandlerFunc`).

- [x] 1.14 `Unmarshal` decoding from path elements
	- [x] 1.14.1 Define how path variables are provided to `EndpointHandler` / `Unmarshal` (router integration).
	- [x] 1.14.2 Map path elements to struct fields using tags and naming conventions.
	- [x] 1.14.3 Add tests for path parameter binding, including missing/extra path elements and type conversion errors.

- [x] 1.15 `Unmarshal` decoding from query parameters
	- [x] 1.15.1 Map query parameters to struct fields using tags and naming conventions.
	- [x] 1.15.2 Support basic types and slices where appropriate.
	- [x] 1.15.3 Add tests for simple, repeated, and missing query parameters.

- [x] 1.15.4 Verify/implement default untagged struct field binding rules
	- [x] 1.15.4.1 Untagged fields: attempt path binding first, then query.
	- [x] 1.15.4.2 Default parameter name: lower-case Go field name.
	- [x] 1.15.4.3 Add tests for default name + default source precedence.

- [x] 1.15.A `Unmarshal` decoding from headers
	- [x] 1.15.A.1 Map HTTP header values to struct fields using tags and naming conventions.
	- [x] 1.15.A.2 Support basic types and slices where appropriate (e.g., repeated headers).
	- [x] 1.15.A.3 Add tests for canonicalization/case-insensitivity and missing headers.

- [x] 1.15.B `Unmarshal` decoding from cookies
	- [x] 1.15.B.1 Map request cookies to struct fields using tags and naming conventions.
	- [x] 1.15.B.2 Support basic types and slices where appropriate.
	- [x] 1.15.B.3 Add tests for missing cookies, repeated cookie names behavior (if any), and URL-escaped values.

- [x] 1.16 `Unmarshal` decoding from form-encoded POST bodies
	- [x] 1.16.1 Support `application/x-www-form-urlencoded` fields mapped via tags.
	- [x] 1.16.2 Support `multipart/form-data` fields for non-file values.
	- [x] 1.16.3 Add tests for both form-encoded and multipart forms.

- [x] 1.17 `Unmarshal` decoding for file uploads
	- [x] 1.17.1 Define field types or helper abstractions for uploaded files (metadata + content).
	- [x] 1.17.2 Add tests covering single and multiple file uploads, missing files, and large file behavior where practical.

- [x] 1.18 `Unmarshal` decoding from JSON request bodies
	- [x] 1.18.1 Support decoding JSON-encoded request bodies into the `params` value.
	- [x] 1.18.2 Define precedence and interaction with other parameter sources (path, query, form).
	- [x] 1.18.3 Handle JSON decoding errors using appropriate error renderers.
	- [x] 1.18.4 Add tests for valid/invalid JSON and mixed-source scenarios.

### 1.C Integration & examples

- [x] 1.19 Integrate the new pattern in at least one representative endpoint (non-breaking example usage).
- [x] 1.20 Update relevant documentation and comments to describe:
	- [x] 1.20.1 The handler/renderer pattern.
	- [x] 1.20.2 All supported renderer types.
	- [x] 1.20.3 All supported parameter sources and struct tag conventions.

### 1.D Testing

- [x] 1.21 Add unit tests for `EndpointHandler` and `Unmarshal` decoding
	- [x] 1.21.1 nil `EndpointFunc`.
	- [x] 1.21.2 nil `Renderer`.
	- [x] 1.21.3 Successful render path.
	- [x] 1.21.4 Endpoint error path.
	- [x] 1.21.5 Processor chain invocation order.
	- [x] 1.21.6 Processor error path.
	- [x] 1.21.7 Renderer error path.
	- [x] 1.21.8 Parameter decoding from each supported source:
		- Path elements.
		- Query parameters.
		- Headers.
		- Cookies.
		- Form-encoded POST body (non-file fields).
		- File uploads.
		- JSON body.

- [x] 1.22 Add unit tests for renderer types
	- [x] 1.22.1 Plain text, HTML, JSON.
	- [x] 1.22.2 Template-based rendering (text and HTML templates).
	- [x] 1.22.3 Static file rendering (including missing/unreadable file behavior).
	- [x] 1.22.4 Directory listing rendering.
	- [x] 1.22.5 Common HTTP error renderers.
	- [x] 1.22.6 Cookie-modifying renderers/helpers.

## 1.E Checklist fixes (spec alignment)

- [x] 1.23 Ensure `EndpointHandler` uses `Unmarshal(...)` exclusively for parameter decoding.
- [x] 1.24 Ensure repeated header/cookie decoding into slice fields is supported (per spec) and tested.


## 2. Validation

- [x] 2.1 `go test ./...` passes.
- [x] 2.2 `openspec validate add-endpoint-processor-handler --strict` passes.
