## MODIFIED Requirements

### Requirement: HTTP endpoint function / processor / renderer abstraction
The system MUST provide a handler type for HTTP endpoints that separates request handling, parameter decoding, and response rendering.

#### Scenario: Endpoint function signature and endpoint adapter
- **WHEN** a new HTTP endpoint is implemented
- **THEN** it MAY be implemented using an endpoint adapter type, `EndpointHandler`, that implements `http.Handler` (a net/http handler) and wraps a single endpoint function.
- **AND** the wrapped endpoint function, with type `EndpointFunc`, MUST accept a response writer, request, and decoded params, and return a `Renderer` and an `error`.
- **AND** the system MUST provide a generic form of `EndpointFunc` for compile-time type safety over the `params` value:
	- `type EndpointFunc[P any] func(w http.ResponseWriter, r *http.Request, params P) (Renderer, error)`
- **AND** the `params` argument type `P` MUST be either:
	- a struct type, or
	- a pointer to a struct type
- **AND** the endpoint adapter MUST populate `params` using the decoder described below.
- **AND** the endpoint adapter MUST invoke the `EndpointFunc`.
- **AND** if the `EndpointFunc` returns a nil error, the endpoint adapter MUST use the returned `Renderer` to write the HTTP response.
- **AND** if the `EndpointFunc` returns a non-nil error, the endpoint adapter MUST handle it following the error handling process described below.
- **AND** the endpoint adapter MUST support applying a middleware processor chain around the endpoint function execution.
- **AND** WHEN an endpoint adapter with a processor chain handles a request, it MUST run zero or more processors in order and then terminate in exactly one `Renderer` returned by the endpoint function or an error.

#### Scenario: Response responsibilities (endpoint vs renderer)
- **WHEN** an `EndpointFunc` is invoked and returns a `Renderer` (and nil error)
- **THEN** the returned `Renderer` MUST be responsible for:
	- writing the response body
	- selecting the HTTP status code
	- setting content-dependent headers such as `Content-Type`, `Content-Length` and `Content-Range` (if applicable)
- **AND** the presence of `http.ResponseWriter` in the `EndpointFunc` signature does not change the renderer responsibility described above.
- **AND** the specification is silent on whether an `EndpointFunc` may set additional response headers via the provided `http.ResponseWriter`.

#### Scenario: Middleware processor chain
- **WHEN** an endpoint response needs multiple response concerns applied (e.g., set headers/cookies and then render JSON)
- **THEN** the endpoint adapter MUST provide a mechanism for running zero or more processors before calling the `EndpointFunc`.
- **AND** the mechanism MUST invoke each `Processor` ordered by position in the chain.
- **AND** unless the request handling is short-circuited (e.g. by a processor handling the request), the endpoint adapter MUST invoke exactly one top-level `EndpointFunc` call.
- **AND** if the `EndpointFunc` returns a nil error, the endpoint adapter MUST invoke exactly the one `Renderer` returned by the `EndpointFunc`.
- **AND** processors MUST either call `next(...)`, return a non-nil error, or terminate the request handling (short-circuit).
- **AND** if any processor returns a non-nil error, processing MUST stop and the adapter must follow the error handling process described below.
- **AND** if the `EndpointFunc` returns a non-nil error, processing MUST stop and the adapter must follow the error handling process described below.
- **AND** if the renderer returns a non-nil error, the request MUST be treated as failed and the error MUST be returned.

#### Scenario: Constructing the HTTP response
- **WHEN** an `EndpointFunc` for an HTTP endpoint returns a `Renderer` and a nil error
- **THEN** the `Renderer` MUST be responsible for writing the HTTP response into a `http.ResponseWriter`.
- **AND** the `Renderer` interface MUST consist of a single `Render` method that takes only the output inputs:
	- `Render(w http.ResponseWriter, r *http.Request) error`
- **AND** the system MUST provide a distinct processor protocol for middleware-style concerns.
- **AND** the `Processor` interface MUST consist of a single `Process` method:
	- `Process(w http.ResponseWriter, r *http.Request, next func(w http.ResponseWriter, r *http.Request) error) error`
- **AND** a `Renderer` MUST call `w.WriteHeader(...)` (directly, or indirectly by writing the response body).
- **AND** a `Processor` MUST NOT call `w.WriteHeader(...)`.
- **AND** a `Processor` MUST NOT write to the response body.
- **AND** processors MAY mutate the response headers or cookies before calling `next(...)`.

#### Scenario: Deferred Hooks
- **WHEN** a processor needs to perform actions immediately before the response headers are committed (e.g., writing cookies)
- **THEN** the endpoint adapter MUST provide a mechanism to register deferred functions.
- **AND** the system MUST provide a `Defer(ctx context.Context, fn func(http.ResponseWriter))` function to register a hook.
- **AND** the registered hooks MUST be executed in LIFO (Last-In-First-Out) order.
- **AND** the endpoint adapter MUST provide a `Commit(ctx context.Context, w http.ResponseWriter)` function that executes all registered hooks.
- **AND** the endpoint adapter MUST call `Commit` immediately before the renderer is invoked or an error response is written.
- **AND** hooks MUST be executed exactly once per request.

#### Scenario: Renderer termination
- **WHEN** a renderer completes successfully
- **THEN** the HTTP response status line MUST have been sent (either via an explicit `w.WriteHeader(...)` call or by writing the response body).
- **AND** the `Renderer` implementations MUST support rendering responses as plain text, HTML, and JSON.
- **AND** the `Renderer` implementations MUST support using Go `text/template` and `html/template` templates as rendering strategies.
- **AND** the concrete `Renderer` implementations MAY encapsulate additional output strategies in the future without breaking the high-level contract described here.

#### Scenario: Renderer cleanup
- **WHEN** a `Renderer` holds resources that require cleanup (e.g., open file descriptors)
- **THEN** the `Renderer` implementation MUST implement `io.Closer` or provide a mechanism to release those resources.
- **AND** the endpoint adapter MUST inspect the returned `Renderer` to check if it implements `io.Closer`.
- **AND** if the `Renderer` implements `io.Closer`, the endpoint adapter MUST ensure `Close()` is called after `Render()` completes or if `Render()` is skipped (e.g. due to panic or error), typically via `defer`.

#### Scenario: Error handling
- **WHEN** an `EndpointFunc` or a processor or a renderer needs to signal an error
- **THEN** the system MUST represent these errors as ordinary Go `error` values.
- **AND** the endpoint adapter MUST be responsible for translating errors returned by the processor chain, endpoint function, or decoder into appropriate HTTP status codes.
- **AND** the project MUST define a dedicated error type that carries:
	- an HTTP status code
	- a human-readable, textual description
- **AND** if an error is of that type, the endpoint adapter MUST map it to an HTTP response whose status code matches the error's status.
- **AND** if an error is not of that type, the endpoint adapter MUST treat it as an internal error (HTTP 500) according to project conventions.

#### Scenario: Decoder contract (stdlib-style Unmarshal)
- **WHEN** the endpoint adapter needs to populate the `params` argument for an `EndpointFunc`
- **THEN** the system MUST define a decoder modeled after Go standard library patterns (e.g., `encoding/json.Unmarshal`).
- **AND** the decoder MUST expose an `Unmarshal` function with the signature:
	- `Unmarshal(r *http.Request, params any) error`
- **AND** the decoder MUST be usable independently of the endpoint adapter, including from ordinary net/http handlers that implement `http.Handler` or `http.HandlerFunc`.
- **AND** `params` MUST be a non-nil pointer to a settable value (typically a pointer to a struct); otherwise `Unmarshal` MUST return a non-nil error.
- **AND** `Unmarshal` MUST decode request data into `params` as directed by the runtime type information of `params`.
- **AND** `Unmarshal` MUST support decoding JSON request into non-struct fields when directed by `json` encoding options (e.g., decoding a JSON array into a field of type `[]string`).
- **AND** decoding must treat syntactic constraints on parameters as decoding errors (e.g., a value that cannot be parsed as an integer, a malformed base64 string, or a value exceeding a maximum length constraint).
- **AND** the endpoint adapter MUST be responsible for translating these decoding errors to an HTTP 400 Bad Request response.
- **AND** `Unmarshal` MUST support populating `params` from the following request data sources when applicable:
	- path elements (variables captured from the URL path)
	- query parameters
	- headers
	- cookies
	- form-encoded bodies (including `multipart/form-data` and file uploads)
	- request bodies
- **AND** the decoder MUST determine how to map request data into `params` by inspecting the type of `params` and applying Go struct tags to map fields to parameter sources and names.
- **AND** fields in `params` without matching data in any applicable source MUST retain their zero value unless otherwise directed by tags or type-specific decoding rules.

#### Scenario: Multiple source tags on a single field (precedence)
- **WHEN** a struct field declares more than one supported source tag (e.g., `path`, `query`, `form`, `body`, `cookie`, `header`)
- **THEN** the decoder MUST attempt binding from sources in the following precedence order:
	- `path`
	- `query`
	- `form`
	- `body`
	- `cookie`
	- `header`
- **AND** the first source in that order that produces a value MUST win and no lower-precedence sources for that field may override it.

#### Scenario: Length constraints via `maxLength` tag
- **WHEN** a `params` struct field declares a `maxLength` struct tag with a positive integer value
- **THEN** the decoder MUST treat that value as the maximum allowed length (in bytes/characters of the raw string value) for that field when binding from textual sources (e.g., path, query, header, cookie, form).
- **AND** if the incoming value exceeds the maximum length, `Unmarshal` MUST return a non-nil error.
- **AND** the endpoint adapter SHOULD map that error to an HTTP 400 Bad Request.
- **AND** if the `maxLength` tag is absent, the decoder MUST enforce a default limit of 16KB (16384 bytes).
- **AND** a `maxLength` tag value of empty string or `0` MUST be treated as "no limit".

- **WHEN** the root `params` struct declares an underscore field named `_` with a `maxLength` tag
- **THEN** the decoder MAY use that value as a configuration for maximum multipart form parsing memory (i.e., the `ParseMultipartForm` limit), according to project conventions.

#### Scenario: Untagged struct fields (default name and source)
- **WHEN** a field on a struct `params` value has no explicit source tags (e.g., no `path:"..."`, `query:"..."`, `header:"..."`, `cookie:"..."`, `form:"..."`)
- **AND** the field type is not a struct type
- **THEN** the default decoding behavior for that field MUST be:
	- first attempt to bind from a path parameter
	- if no matching path parameter exists, attempt to bind from a query parameter
- **AND** the default parameter name for both the path and query lookups MUST be the lower-case form of the Go field name.

#### Scenario: Tagged fields with empty parameter name (default name)
- **WHEN** a field has an explicit source tag (e.g., `query`, `path`, `header`, `cookie`, `form`) but the tag does not specify a parameter name
- **THEN** the decoder MUST use the lower-case form of the Go field name as the default parameter name for that source.

- **AND** for `body` tags, the name element is ignored for body decoding purposes (and may be empty).

#### Scenario: Ignoring fields via "-" tag value (and literal "-" parameter names)
- **WHEN** a field has a supported parameter source tag (e.g., `query`, `path`, `header`, `cookie`, `form`, `body`) whose raw tag value is exactly `"-"` (with no comma)
- **THEN** the decoder MUST interpret that tag as an instruction to ignore the field for that source.
- **AND** the decoder MUST NOT attempt to populate it from that request data source.

- **WHEN** a field has a supported parameter source tag whose raw tag value begins with `"-,"` (e.g., `query:"-,"`)
- **THEN** the decoder MUST treat the parameter name as the literal string `"-"` for that source.
- **AND** decoding MUST proceed normally (subject to any other options present).

#### Scenario: Encoding options on source tags
- **WHEN** a supported parameter source tag contains options after the name (i.e., `name,option...`)
- **THEN** the decoder MUST support the following encoding options:
	- `base64` (standard base64)
	- `base64url` (URL-safe base64)
	- `json`
- **AND** a tag MUST NOT specify more than one encoding option among `base64`, `base64url`, and `json`; if more than one is present, `Unmarshal` MUST return a non-nil error.

#### Scenario: Type-specific decoding via `encoding.TextUnmarshaler`
- **WHEN** a destination field's type implements `encoding.TextUnmarshaler`
- **THEN** the decoder MUST use that type's `UnmarshalText([]byte)` method to decode textual source values instead of the default type conversions.
- **AND** if the field type implements `encoding.TextUnmarshaler` only via a pointer receiver, the decoder MUST support that as well.
- **AND** if the field type implements `encoding.TextUnmarshaler`, the decoder MUST NOT recursively decode into its internal struct fields.
- **AND** if a source tag specifies the `json` encoding option, the decoder MUST decode using JSON into the destination field and MUST NOT use `encoding.TextUnmarshaler` for that field.

#### Scenario: Encoding option semantics (`base64`, `base64url`, `json`)
- **WHEN** an encoding option of `base64` or `base64url` is specified
- **THEN** the decoder MUST treat the source value as base64-encoded bytes and decode it prior to assignment.
- **AND** the decoder MUST support this option only when the destination field type is `[]byte`; otherwise `Unmarshal` MUST return a non-nil error.

- **WHEN** an encoding option of `json` is specified
- **THEN** the decoder MUST treat the source value as JSON and decode it into the destination field using the destination field's type.
- **AND** the decoder MUST support `json` for `body`-tagged fields.
- **AND** the decoder MUST support `json` for non-body tags (e.g., decoding a JSON object stored in a header or query value).

#### Scenario: Repeated query params, headers, and cookies into slice fields
- **WHEN** a field is tagged as a `query`, `header`, or `cookie` parameter
- **AND** the destination field is a slice type whose element type is supported for decoding from a single header/cookie value
- **THEN** `Unmarshal` MUST reset the slice to length 0 (if initialized) and then append one element to the slice for each matching value in the request.
- **AND** “matching values” means:
	- for query params: all values for that key in `r.URL.Query()`
	- for headers: all values returned by the request header map for that header name
	- for cookies: all cookies in the request whose `Name` matches the parameter name

#### Scenario: Body decoding (single `body` field)
- **WHEN** a struct field is tagged with `body:"..."`
- **THEN** the decoder MUST treat that field as the single destination for decoding the entire request body.
- **AND** the `body` tag value MUST follow the standard tag format of `name,option...`.
- **AND** the first element (name) is ignored for body decoding purposes but determines the position of options.
- **AND** at most one `body`-tagged field is supported per `params` struct; if more than one `body` field is present, `Unmarshal` MUST return a non-nil error.

#### Scenario: Body encoding selection
- **WHEN** a `body`-tagged field specifies `json` as an option (e.g. `body:",json"` or `body:"placeholder,json"`)
- **THEN** the decoder MUST decode the request body as JSON into that field.
- **AND** `Unmarshal` MUST validate that the request `Content-Type` matches the selected encoding (e.g., `application/json` for `json` encoding); if it does not, `Unmarshal` MUST return a non-nil error.

#### Scenario: Default body decoding rules (by `Content-Type` and field type)
- **WHEN** a `body`-tagged field does not specify an explicit encoding
- **THEN** the decoder SHOULD select the default body decoding strategy using the request `Content-Type` and the field type.
- **AND** the default rules SHOULD be:
	- if `Content-Type` is `application/json` (or has the `application/json` media type), decode JSON into the field when the field type is not `string` or `[]byte`.
	- if the destination field type is `string`, read the entire request body and assign it as a string (bytes-to-string) regardless of `Content-Type`.
	- if the destination field type is `[]byte`, read the entire request body and assign the raw bytes regardless of `Content-Type`.
	- otherwise, treat the body as not directly decodable and return a 415 Unsupported Media Type error

#### Scenario: File uploads in form-encoded POST bodies
- **WHEN** an HTTP request with a form-encoded POST body contains file uploads (e.g., `multipart/form-data`)
- **THEN** the endpoint adapter MUST be able to bind uploaded file metadata and content to fields on the `params` value according to struct tags.
- **AND** the project MAY define specific field types or helper abstractions to represent uploaded files (e.g., file name, size, MIME type, and stream or byte content).
- **AND** large file content handling (e.g., streaming vs buffering) MAY be controlled by project-specific conventions and is not mandated by this requirement.

#### Scenario: Plain text response renderer
- **WHEN** an endpoint returns a plain-text response
- **THEN** the system MUST provide a terminal `Renderer` implementation named `StringRenderer`.
- **AND** `StringRenderer` MUST set `Content-Type` to `text/plain; charset=utf-8` when no content type has already been set.
- **AND** `StringRenderer` MUST write the response body from a string value.
- **AND** `StringRenderer` MUST default the status code to 200 when no status has been set.

#### Scenario: Renderer support for static files and directories
- **WHEN** an `EndpointFunc` for an HTTP endpoint returns a `Renderer` configured with a static file path (and nil error)
- **THEN** the `Renderer` MUST produce an HTTP response whose body is the file content.
- **AND** the `Renderer` MUST set the `Content-Type` header to an appropriate MIME type for the file.
- **AND** the `Renderer` MUST set the `Last-Modified` (or equivalent) header based on the file's modification timestamp.
- **AND** if the file does not exist or cannot be read, the `Renderer` MUST indicate an appropriate HTTP error (e.g., 404 or 500) according to project conventions.

- **WHEN** an `EndpointFunc` for an HTTP endpoint returns a `Renderer` configured with a directory path (and nil error)
- **THEN** the `Renderer` MUST produce an HTTP response that lists the directory contents.
- **AND** the directory listing MAY be rendered using a configurable HTML template.
- **AND** the directory listing response MUST set an appropriate `Content-Type` (e.g., `text/html`).

#### Scenario: Secure-cookie session middleware
- **WHEN** an HTTP endpoint needs session state to be available consistently across requests
- **THEN** the system MUST provide a middleware mechanism implemented using processors.
- **AND** the middleware MUST configure a `SecureCookie` codec for encoding and decoding session data.
- **AND** the middleware MUST interact with the request cookies to load and store session state.
- **AND** the middleware MUST make the session available to downstream renderers and the wrapped `EndpointFunc` (e.g., via `context.Context` on `*http.Request`).
- **AND** the middleware MUST persist session changes by setting the secure session cookie on the response.
- **AND** the middleware MUST use the deferred hook mechanism to write the session cookie before headers are committed.

- **AND** if the secure cookie cannot be verified or decoded, the middleware MUST treat the request as having an empty session (and MAY clear the cookie).
- **AND** the middleware MUST NOT fail the entire request solely due to an unreadable session cookie.

- **AND** the project MUST define the session serialization format and size limits such that typical session data fits within browser cookie limits.

#### Scenario: Secure Cookie Codec
- **WHEN** a secure cookie needs to be created or read
- **THEN** the system MUST provide a `SecureCookie` type that handles encoding and decoding of cookie values.
- **AND** the `SecureCookie` MUST support authenticated encryption (e.g., ChaCha20-Poly1305) to ensure confidentiality and integrity.
- **AND** the `SecureCookie` MUST support serializing arbitrary Go types into the cookie value (e.g., using CBOR or JSON).
- **AND** the `SecureCookie` MUST allow configuring default cookie attributes (Name, Domain, Path, Secure, HttpOnly, SameSite).
- **AND** the `SecureCookie` MUST provide an `Encode(value any, maxAge int) (*http.Cookie, error)` method.
- **AND** the `SecureCookie` MUST provide a `Decode(cookie *http.Cookie, v any) error` method.
- **AND** the `SecureCookie` MUST provide a `Clear() *http.Cookie` method to generate a deletion cookie.
- **AND** the `SecureCookie` MUST provide a `Name() string` method to retrieve the configured cookie name.
