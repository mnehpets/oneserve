## Why

oneserve currently supports HTTP endpoints with JSON responses, but lacks a structured protocol for remote procedure calls. JSON-RPC v2 is widely adopted in modern protocols like **Model Context Protocol (MCP)** and **Language Server Protocol (LSP)**, enabling standardized method invocation, batch requests, and structured error handling. Adding this support makes oneserve suitable for building AI tooling, IDE integrations, and services that benefit from a the RPC client-server model.

## What Changes

- Add a new JSON-RPC v2 server implementation (custom implementation chosen over `filecoin-project/go-jsonrpc` due to HTTP status code impedance mismatch - go-jsonrpc returns HTTP 400/500 for JSON-RPC errors, but spec requires 200 OK with error in body)
- Integrate with existing endpoint/processor architecture using the `endpoint.Handler()` pattern
- Support method registration, parameter validation, and structured responses
- Provide handlers for both single and batch requests per JSON-RPC v2 spec (required by MCP)

## Capabilities

### New Capabilities
- `jsonrpc-server`: JSON-RPC v2 endpoint with `JSONRPCEndpoint` type, method registration via `Register(namespace, receiver)`, integration via `endpoint.Handler(e.Endpoint, processors...)`, request parsing, parameter validation, response rendering, batch support, and error code mapping

### Modified Capabilities
- (none - this is an additive feature)

## Impact

- New `jsonrpc` package for JSON-RPC handling
- New example demonstrating JSON-RPC usage in `example/jsonrpc/main.go`
- Package godoc documentation
- No breaking changes to existing code
