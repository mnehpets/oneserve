// Package jsonrpc provides a JSON-RPC 2.0 server endpoint integrated with oneserve's processor chain.
//
// This package implements the JSON-RPC 2.0 specification (https://www.jsonrpc.org/specification)
// and JSON-RPC over HTTP (https://www.simple-is-better.org/json-rpc/transport_http.html).
//
// # Basic Usage
//
// Create an endpoint, register methods, and serve via HTTP:
//
//	e := jsonrpc.NewEndpoint()
//	e.Register("math", &MathMethods{})
//	http.Handle("/rpc", endpoint.Handler(e.Endpoint))
//	http.ListenAndServe(":8080", nil)
//
// Methods are defined on a struct with a params type:
//
//	type MathMethods struct{}
//
//	type AddParams struct {
//	    A int `json:"a"`
//	    B int `json:"b"`
//	}
//
//	func (m *MathMethods) Add(ctx context.Context, params AddParams) (int, error) {
//	    return params.A + params.B, nil
//	}
//
// # Method Signatures
//
// Methods must have this signature:
//
//	func(ctx context.Context, params <StructType>) (result, error)
//
// The params struct uses json tags to define parameter names. Use an empty
// struct for methods with no parameters:
//
//	func (m *Methods) Ping(ctx context.Context, params struct{}) (string, error)
//
// Methods support both positional (array) and named (object) parameters.
//
// # Namespaces
//
// The namespace prefixes method names. Use empty string for no prefix:
//
//	e.Register("math", &MathMethods{})  // -> "math.Add"
//	e.Register("", &MathMethods{})      // -> "Add"
//
// # Method Name Override
//
// Use a `_` field with a `jsonrpc` tag to override the method name:
//
//	type AddParams struct {
//	    _ struct{} `jsonrpc:"add"`  // method name becomes lowercase "add"
//	    A int `json:"a"`
//	    B int `json:"b"`
//	}
//
// # Error Handling
//
// Return JSONRPCError for protocol-level errors:
//
//	return 0, jsonrpc.NewError(jsonrpc.CodeInvalidParams, "division by zero")
//
// Standard error codes are defined as constants:
//   - CodeParseError (-32700)
//   - CodeInvalidRequest (-32600)
//   - CodeMethodNotFound (-32601)
//   - CodeInvalidParams (-32602)
//   - CodeInternalError (-32603)
//
// # Processor Integration
//
// Processors can be passed to endpoint.Handler for cross-cutting concerns:
//
//	http.Handle("/rpc", endpoint.Handler(e.Endpoint, authProcessor, loggingProcessor))
//
// Processor errors return HTTP error responses (not JSON-RPC errors).
package jsonrpc
