## 1. Setup

- [x] 1.1 Create `jsonrpc` package directory structure
- [x] 1.2 Evaluate `filecoin-project/go-jsonrpc` - decided against due to HTTP status code impedance mismatch

## 2. Core Types

- [x] 2.1 Define `JSONRPCEndpoint` struct with method registry
- [x] 2.2 Define `JSONRPCError` type with code, message, and data fields
- [x] 2.3 Implement `Error() string` method on `JSONRPCError` for error interface
- [x] 2.4 Define constants for standard error codes (-32700, -32600, -32601, -32602, -32603)

## 3. Endpoint Implementation

- [x] 3.1 Implement `NewEndpoint() *JSONRPCEndpoint` constructor
- [x] 3.2 Implement `Endpoint(w http.ResponseWriter, r *http.Request, params rpcParams) (endpoint.Renderer, error)` method
- [x] 3.3 Add POST-only request validation (return 405 for other methods)
- [x] 3.4 Implement `jsonrpcRenderer` for response rendering
- [x] 3.5 Implement `handleBody()` for request processing with batch support

## 4. Method Registration

- [x] 4.1 Implement `Register(namespace string, receiver interface{})` method
- [x] 4.2 Support empty namespace for direct method names (e.g., `foobar` → `Foobar`)
- [x] 4.3 Add godoc documentation for registration pattern

## 5. Error Handling

- [x] 5.1 Implement error to JSON-RPC error code mapping
- [x] 5.2 Handle parse errors (invalid JSON) → code -32700
- [x] 5.3 Handle invalid request errors → code -32600
- [x] 5.4 Handle method not found → code -32601
- [x] 5.5 Handle invalid params → code -32602
- [x] 5.6 Handle internal errors → code -32603
- [x] 5.7 Support custom error codes via `JSONRPCError` type

## 6. Unit Tests

- [x] 6.1 Test endpoint integrates with endpoint.Handler
- [x] 6.2 Test POST-only enforcement
- [x] 6.3 Test method registration with namespace
- [x] 6.4 Test method registration without namespace
- [x] 6.5 Test single request handling (success case)
- [x] 6.6 Test notification handling (no id → 204 No Content)
- [x] 6.7 Test batch request handling
- [x] 6.8 Test empty batch request → Invalid Request error
- [x] 6.9 Test all standard error codes
- [x] 6.10 Test custom error codes (JSONRPCError type)
- [x] 6.11 Test processor chain execution
- [x] 6.12 Test context propagation to methods
- [x] 6.13 Test Content-Type header validation (415 Unsupported Media Type)
- [x] 6.14 Test Accept header validation (406 Not Acceptable)
- [x] 6.15 Test Content-Length header in response
- [x] 6.16 Test Content-Length for batch responses

## 7. Example and Documentation

- [x] 7.1 Create example in `example/jsonrpc/main.go` demonstrating basic usage
- [x] 7.2 Add godoc package documentation with usage examples
