## Context

oneserve provides an HTTP endpoint abstraction with `EndpointHandler`, `Renderer`, and `Processor` interfaces designed around **HTTP request/response semantics**. Adding JSON-RPC v2 support requires adapting the stack because JSON-RPC has different response semantics:

- **HTTP endpoint**: `Renderer` writes response body, sets status codes, headers
- **JSON-RPC**: Response is always 200 OK with structured JSON body containing result or error

The `Processor` chain remains useful for cross-cutting concerns like bearer authentication, logging, and request validation - these apply equally to REST and RPC. The implementation uses the existing `Renderer` abstraction: the endpoint function returns a `jsonrpcRenderer` that produces protocol-compliant JSON.

**Existing libraries evaluated:**
- `filecoin-project/go-jsonrpc`: Mature but has HTTP status code bug - returns HTTP 400/500 for JSON-RPC errors, while the spec requires HTTP 200 OK with error in the response body.
- `gorilla/rpc/json`: Codec-based, requires explicit codec registration, less ergonomic.
- `net/rpc/jsonrpc`: Stdlib, but uses older JSON-RPC 1.0 style and requires connection-level handling.

## Goals / Non-Goals

**Goals:**
- JSON-RPC 2.0 compliant server handler
- Single and batch request support (required for MCP compatibility)
- Support method registration with parameter validation
- Map errors to JSON-RPC error codes
- Integrate with existing `Processor` chain for auth, logging, etc.

**Non-Goals:**
- WebSocket transport
- Notifications (server-to-client push without request)

## Decisions

### 1. Wrap `filecoin-project/go-jsonrpc` vs. custom implementation

**Decision:** Build a custom implementation.

**Rationale:**
- `go-jsonrpc` returns HTTP 400/500 for JSON-RPC errors, violating spec (requires HTTP 200 OK with error in body)
- Custom implementation gives full control over HTTP status code handling
- Simpler error code registration without complex error type mapping
- Total implementation is ~400 lines - manageable to maintain

**Trade-off:** More code to maintain, but ensures spec compliance.

### 2. Processor Chain Integration

**Decision:** `JSONRPCEndpoint` integrates via the standard `endpoint.Handler()` pattern.

**Approach:**
```go
e := jsonrpc.NewEndpoint()
e.Register("math", &MathMethods{})
http.Handle("/rpc", endpoint.Handler(e.Endpoint, processors...))
```

Processors run before the endpoint function. The endpoint returns a `jsonrpcRenderer` that handles response formatting.

### 3. Method Registration Pattern

**Decision:** Register a struct with exported methods. Method names map to RPC method names with optional namespace prefix.

**Example:**
```go
type MathMethods struct{}

func (m *MathMethods) Add(ctx context.Context, a, b int) (int, error) {
    return a + b, nil
}

e.Register("math", &MathMethods{})
// -> methods: "math.Add"
```

### 4. Error Code Mapping

**Decision:** Define a `JSONRPCError` type that carries the standard JSON-RPC error codes. Methods return this type for protocol-level errors; other errors default to InternalError (-32603).

**Standard codes:**
- `-32700`: Parse error
- `-32600`: Invalid request
- `-32601`: Method not found
- `-32602`: Invalid params
- `-32603`: Internal error

### 5. Body Tag for Raw Request Body

**Decision:** Use `[]byte` with `body:""` tag to capture raw request body.

**Rationale:**
- Using `body:",json"` with `json.RawMessage` caused the framework to attempt JSON parsing and return HTTP 400 on invalid JSON
- JSON-RPC requires HTTP 200 OK with parse error in the body for invalid JSON
- Raw `[]byte` defers parsing to the endpoint handler, allowing proper JSON-RPC error responses

## Risks / Trade-offs

| Risk | Mitigation |
|------|------------|
| Custom implementation requires ongoing maintenance | Implementation is ~400 lines; comprehensive test coverage |
| Batch request memory exhaustion | Document max batch size recommendations; consider configurable limits |
| Processors run per HTTP request, not per RPC call in a batch | Document this behavior; processors see the entire batch as one request |
