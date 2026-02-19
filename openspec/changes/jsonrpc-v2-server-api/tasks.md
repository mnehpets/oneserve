## 1. Setup

- [ ] 1.1 Create `jsonrpc` package directory structure
- [ ] 1.2 Evaluate `filecoin-project/go-jsonrpc` - decided against due to HTTP status code impedance mismatch

## 2. Core Types

- [ ] 2.1 Define `JSONRPCEndpoint` struct with method registry
- [ ] 2.2 Define `JSONRPCError` type with code, message, and data fields
- [ ] 2.3 Implement `Error() string` method on `JSONRPCError` for error interface
- [ ] 2.4 Define constants for standard error codes (-32700, -32600, -32601, -32602, -32603)

## 3. Endpoint Implementation

- [ ] 3.1 Implement `NewEndpoint() *JSONRPCEndpoint` constructor
- [ ] 3.2 Implement `Endpoint(w http.ResponseWriter, r *http.Request, params rpcParams) (endpoint.Renderer, error)` method
- [ ] 3.3 Add POST-only request validation (return 405 for other methods)
- [ ] 3.4 Implement `jsonrpcRenderer` for response rendering
- [ ] 3.5 Implement `handleBody()` for request processing with batch support

## 4. Method Registration

- [ ] 4.1 Implement `Register(namespace string, receiver interface{})` method
- [ ] 4.2 Support empty namespace for direct method names (e.g., `foobar` → `Foobar`)
- [ ] 4.3 Add godoc documentation for registration pattern

## 5. Error Handling

- [ ] 5.1 Implement error to JSON-RPC error code mapping
- [ ] 5.2 Handle parse errors (invalid JSON) → code -32700
- [ ] 5.3 Handle invalid request errors → code -32600
- [ ] 5.4 Handle method not found → code -32601
- [ ] 5.5 Handle invalid params → code -32602
- [ ] 5.6 Handle internal errors → code -32603
- [ ] 5.7 Support custom error codes via `JSONRPCError` type

## 6. Unit Tests

- [ ] 6.1 Test endpoint integrates with endpoint.Handler
- [ ] 6.2 Test POST-only enforcement
- [ ] 6.3 Test method registration with namespace
- [ ] 6.4 Test method registration without namespace
- [ ] 6.5 Test single request handling (success case)
- [ ] 6.6 Test notification handling (no id → 204 No Content)
- [ ] 6.7 Test batch request handling
- [ ] 6.8 Test empty batch request → Invalid Request error
- [ ] 6.9 Test all standard error codes
- [ ] 6.10 Test custom error codes (JSONRPCError type)
- [ ] 6.11 Test processor chain execution
- [ ] 6.12 Test context propagation to methods

## 7. Example and Documentation

- [ ] 7.1 Create example in `example/jsonrpc/main.go` demonstrating basic usage
- [ ] 7.2 Add godoc package documentation with usage examples
