## ADDED Requirements

### Requirement: JSON-RPC Endpoint Implementation
The system SHALL provide a `JSONRPCEndpoint` type that integrates with the oneserve endpoint architecture for serving JSON-RPC 2.0 requests over HTTP.

#### Scenario: Endpoint integrates with endpoint.Handler
- **WHEN** a `JSONRPCEndpoint` is created
- **THEN** it SHALL provide an `Endpoint(w http.ResponseWriter, r *http.Request, params rpcParams) (endpoint.Renderer, error)` function
- **AND** it SHALL be usable with `endpoint.Handler(e.Endpoint, processors...)` for standard Go HTTP routing

#### Scenario: POST-only requests
- **WHEN** a request with method other than POST is received
- **THEN** the endpoint SHALL return an error with HTTP 405 Method Not Allowed

### Requirement: Method Registration
The system SHALL allow registering method handlers using struct types with exported methods.

#### Scenario: Register namespace with struct
- **WHEN** a struct with exported methods is registered with a namespace
- **THEN** each exported method SHALL be available as `<namespace>.<method>` via JSON-RPC
- **AND** methods SHALL accept `context.Context` as the first parameter
- **AND** methods SHALL return at most two values: a result and an error

#### Scenario: Register methods without namespace
- **WHEN** a struct with exported methods is registered with an empty namespace
- **THEN** each exported method SHALL be available as `<method>` (no prefix) via JSON-RPC
- **AND** a request with method name `foobar` SHALL invoke the `Foobar` method

#### Scenario: Method parameter types
- **WHEN** a method is invoked via JSON-RPC
- **THEN** parameters from the request SHALL be unmarshaled into the method's parameter types
- **AND** basic types (string, int, float, bool) SHALL be supported
- **AND** struct types SHALL be supported
- **AND** slice and map types SHALL be supported

### Requirement: JSON Encoding
The system SHALL use standard Go `encoding/json` for all JSON marshalling and unmarshalling.

#### Scenario: Request unmarshalling
- **WHEN** a JSON-RPC request body is parsed
- **THEN** the system SHALL use `encoding/json.Unmarshal` with standard Go JSON rules
- **AND** struct field tags (e.g., `json:"fieldName"`) SHALL be respected

#### Scenario: Response marshalling
- **WHEN** a JSON-RPC response is serialized
- **THEN** the system SHALL use `encoding/json.Marshal` with standard Go JSON rules
- **AND** struct field tags SHALL be respected for result serialization

#### Scenario: Raw body capture for parse error handling
- **WHEN** a request body is received
- **THEN** the system SHALL capture the raw body as `[]byte` using the `body:""` tag
- **AND** JSON parsing SHALL be deferred to allow proper JSON-RPC error responses for parse errors

### Requirement: Single Request Handling
The system SHALL handle single JSON-RPC 2.0 requests conforming to the specification.

#### Scenario: Valid single request
- **WHEN** a valid JSON-RPC request is received with `jsonrpc: "2.0"`, a valid `method`, optional `params`, and an `id`
- **THEN** the handler SHALL invoke the registered method
- **AND** respond with a JSON object containing `jsonrpc: "2.0"`, the same `id`, and either `result` or `error`

#### Scenario: Request without id (notification)
- **WHEN** a JSON-RPC request is received without an `id` field
- **THEN** the handler SHALL process the request
- **AND** respond with HTTP 204 No Content (no response body)

### Requirement: Batch Request Handling
The system SHALL handle batch requests containing an array of JSON-RPC requests.

#### Scenario: Valid batch request
- **WHEN** a JSON array of valid JSON-RPC requests is received
- **THEN** the handler SHALL process each request in the array
- **AND** respond with a JSON array of responses in the same order
- **AND** each response SHALL correspond to its request by `id`

#### Scenario: Mixed batch with notifications
- **WHEN** a batch request contains some requests with `id` and some without
- **THEN** only requests with `id` SHALL be included in the response array
- **AND** notification requests (no `id`) SHALL NOT produce responses

#### Scenario: Empty batch request
- **WHEN** an empty JSON array `[]` is received as a request
- **THEN** the handler SHALL respond with an Invalid Request error (code -32600)

### Requirement: Error Code Mapping
The system SHALL map errors to standard JSON-RPC 2.0 error codes and return HTTP 200 OK with error in the response body.

#### Scenario: HTTP status code for errors
- **WHEN** any JSON-RPC error occurs
- **THEN** the HTTP response status SHALL be 200 OK
- **AND** the error SHALL be in the JSON response body with appropriate error code

#### Scenario: Parse error
- **WHEN** the request body cannot be parsed as valid JSON
- **THEN** the response SHALL include error code -32700 (Parse error)

#### Scenario: Invalid request
- **WHEN** the JSON is valid but not a conforming JSON-RPC request
- **THEN** the response SHALL include error code -32600 (Invalid Request)

#### Scenario: Method not found
- **WHEN** the requested method does not exist
- **THEN** the response SHALL include error code -32601 (Method not found)

#### Scenario: Invalid params
- **WHEN** the method parameters cannot be unmarshaled or are invalid
- **THEN** the response SHALL include error code -32602 (Invalid params)

#### Scenario: Internal error
- **WHEN** a registered method returns a non-nil error
- **THEN** the response SHALL include error code -32603 (Internal error)
- **AND** the error message SHALL NOT expose internal implementation details

#### Scenario: Custom error codes
- **WHEN** a method returns a `JSONRPCError` type
- **THEN** the response SHALL use the error code from the `JSONRPCError`
- **AND** the error message from the `JSONRPCError` SHALL be included in the response

### Requirement: Processor Chain Integration
The system SHALL support running a processor chain before dispatching to RPC methods via the standard `endpoint.Handler()` pattern.

#### Scenario: Processors execute before method dispatch
- **WHEN** a request is received
- **THEN** the processor chain SHALL execute before the endpoint function
- **AND** if a processor returns an error, the method SHALL NOT be invoked
- **AND** a JSON-RPC error response SHALL be returned

#### Scenario: Processor chain sees entire batch as one request
- **WHEN** a batch request is received
- **THEN** the processor chain SHALL execute once for the entire HTTP request
- **AND** processors SHALL NOT be invoked per-individual RPC call within the batch

#### Scenario: Context propagation through processors
- **WHEN** processors modify the request context
- **THEN** the modified context SHALL be available to the RPC method
