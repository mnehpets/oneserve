// Package jsonrpc provides a JSON-RPC 2.0 server endpoint integrated with oneserve's processor chain.
//
// This package implements JSON-RPC 2.0 specification (https://www.jsonrpc.org/specification)
// with support for single requests, batch requests, and notifications.
//
// # Basic Usage
//
// Create an endpoint and register methods:
//
//	type MathMethods struct{}
//
//	func (m *MathMethods) Add(ctx context.Context, a, b int) (int, error) {
//	    return a + b, nil
//	}
//
//	func main() {
//	    e := jsonrpc.NewEndpoint()
//	    e.Register("math", &MathMethods{})
//
//	    http.Handle("/rpc", endpoint.Handler(e.Endpoint))
//	    http.ListenAndServe(":8080", nil)
//	}
//
// # Method Registration Pattern
//
// Methods are registered by providing a struct with exported methods. The namespace
// parameter determines the method name prefix:
//
//	e.Register("math", &MathMethods{})
//	// Methods become: "math.Add", "math.Subtract", etc.
//
// Use an empty namespace for direct method names:
//
//	e.Register("", &Methods{})
//	// Methods become: "Add", "Subtract", etc.
//
// Method signatures must follow one of these patterns:
//
//	func(ctx context.Context, params...) (result, error)
//	func(ctx context.Context, params...) error
//	func(ctx context.Context, params...) result
//	func(params...) (result, error)
//	func(params...) error
//	func(params...) result
//
// # Processor Integration
//
// Processors can be passed to endpoint.Handler for authentication, logging, and other
// cross-cutting concerns:
//
//	e := jsonrpc.NewEndpoint()
//	e.Register("api", &APIMethods{})
//	http.Handle("/rpc", endpoint.Handler(e.Endpoint, authProcessor, loggingProcessor))
//
// If any processor returns an error, the chain stops and an HTTP error response
// is returned (not a JSON-RPC error).
//
// # Error Handling
//
// Return JSONRPCError for protocol-level errors:
//
//	func (m *Methods) Divide(ctx context.Context, a, b int) (int, error) {
//	    if b == 0 {
//	        return 0, jsonrpc.NewInvalidParamsError("division by zero")
//	    }
//	    return a / b, nil
//	}
//
// Any error returned from a method is mapped to a JSON-RPC error. JSONRPCError types
// preserve their code; other errors default to InternalError (-32603).
//
// # Standard Error Codes
//
// The package defines standard JSON-RPC 2.0 error codes:
//   - CodeParseError (-32700): Invalid JSON was received
//   - CodeInvalidRequest (-32600): The JSON sent is not a valid Request object
//   - CodeMethodNotFound (-32601): The method does not exist
//   - CodeInvalidParams (-32602): Invalid method parameter(s)
//   - CodeInternalError (-32603): Internal JSON-RPC error
//
// # Notifications
//
// Requests without an "id" field are treated as notifications. The server executes
// the method but returns no response (HTTP 204 No Content):
//
//	{"jsonrpc":"2.0","method":"log","params":["message"]}
//
// # Batch Requests
//
// Multiple requests can be sent in a single HTTP call as a JSON array:
//
//	[
//	  {"jsonrpc":"2.0","method":"add","params":[1,2],"id":1},
//	  {"jsonrpc":"2.0","method":"add","params":[3,4],"id":2}
//	]
//
// The response is an array of results in the same order.
package jsonrpc
