// Package jsonrpc provides JSON-RPC 2.0 server implementation for oneserve.
//
// This package integrates with the oneserve endpoint architecture to provide
// a JSON-RPC 2.0 compliant server handler supporting single and batch requests.
//
// Basic usage:
//
//	e := jsonrpc.NewEndpoint()
//	e.Register("math", &MathService{})
//	http.Handle("/rpc", endpoint.Handler(e.Endpoint))
//
// Method Registration:
//
// Services are registered as structs with exported methods. Methods receive
// context.Context as the first parameter and return (result, error).
//
//	type MathService struct{}
//
//	func (m *MathService) Add(ctx context.Context, a, b int) (int, error) {
//	    return a + b, nil
//	}
//
//	e.Register("math", &MathService{})  // method available as "math.Add"
//	e.Register("", &MathService{})      // method available as "Add"
//
// Error Handling:
//
// Methods can return standard errors (mapped to -32603 Internal Error) or
// jsonrpc.Error for custom error codes:
//
//	func (m *MathService) Divide(ctx context.Context, a, b int) (int, error) {
//	    if b == 0 {
//	        return 0, jsonrpc.NewError(-32000, "division by zero", nil)
//	    }
//	    return a / b, nil
//	}
package jsonrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"github.com/mnehpets/oneserve/endpoint"
)

// Standard JSON-RPC 2.0 error codes.
const (
	ParseError     = -32700 // Invalid JSON was received
	InvalidRequest = -32600 // The JSON sent is not a valid Request object
	MethodNotFound = -32601 // The method does not exist
	InvalidParams  = -32602 // Invalid method parameter(s)
	InternalError  = -32603 // Internal JSON-RPC error
)

// Error represents a JSON-RPC error with code, message, and optional data.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// NewError creates a new JSON-RPC error.
func NewError(code int, message string, data any) *Error {
	return &Error{Code: code, Message: message, Data: data}
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e == nil {
		return "jsonrpc: error: <nil>"
	}
	return fmt.Sprintf("jsonrpc error %d: %s", e.Code, e.Message)
}

// Request represents a JSON-RPC 2.0 request object.
type Request struct {
	JSONRPC string           `json:"jsonrpc"`
	Method  string           `json:"method"`
	Params  json.RawMessage  `json:"params,omitempty"`
	ID      *json.RawMessage `json:"id,omitempty"`
}

// Response represents a JSON-RPC 2.0 response object.
type Response struct {
	JSONRPC string           `json:"jsonrpc"`
	Result  any              `json:"result,omitempty"`
	Error   *Error           `json:"error,omitempty"`
	ID      *json.RawMessage `json:"id,omitempty"`
}

// methodFunc is a function that can be called to execute a method.
type methodFunc func(ctx context.Context, params json.RawMessage) (any, error)

// Endpoint provides JSON-RPC 2.0 request handling.
type Endpoint struct {
	methods map[string]methodFunc
}

// rpcParams captures the raw request body for JSON-RPC processing.
type rpcParams struct {
	Body []byte `body:""`
}

// NewEndpoint creates a new JSON-RPC endpoint.
func NewEndpoint() *Endpoint {
	return &Endpoint{
		methods: make(map[string]methodFunc),
	}
}

// Endpoint implements the endpoint.EndpointFunc interface for use with endpoint.Handler.
// It handles both single and batch JSON-RPC requests.
func (e *Endpoint) Endpoint(w http.ResponseWriter, r *http.Request, params rpcParams) (endpoint.Renderer, error) {
	// JSON-RPC requires POST requests
	if r.Method != http.MethodPost {
		return nil, endpoint.Error(http.StatusMethodNotAllowed, "JSON-RPC only supports POST", nil)
	}

	// Validate Content-Type header (MUST be application/json)
	contentType := r.Header.Get("Content-Type")
	if !isApplicationJSON(contentType) {
		return nil, endpoint.Error(http.StatusUnsupportedMediaType, "Content-Type must be application/json", nil)
	}

	// Validate Accept header (MUST be application/json)
	accept := r.Header.Get("Accept")
	if accept != "" && !isApplicationJSON(accept) {
		return nil, endpoint.Error(http.StatusNotAcceptable, "Accept must be application/json", nil)
	}

	// Process the request body
	return e.handleBody(params.Body)
}

// isApplicationJSON checks if the content type is application/json
func isApplicationJSON(contentType string) bool {
	// Trim whitespace and convert to lowercase for comparison
	contentType = strings.TrimSpace(strings.ToLower(contentType))
	return contentType == "application/json" || strings.HasPrefix(contentType, "application/json;")
}

// handleBody processes the raw request body and returns an appropriate renderer.
func (e *Endpoint) handleBody(body []byte) (endpoint.Renderer, error) {
	// Check for empty body
	if len(body) == 0 {
		return &jsonrpcRenderer{
			responses: []Response{
				newErrorResponse(nil, InvalidRequest, "Request body is empty", nil),
			},
		}, nil
	}

	// Try to determine if this is a batch request (array) or single request (object)
	body = trimSpace(body)
	if len(body) == 0 {
		return &jsonrpcRenderer{
			responses: []Response{
				newErrorResponse(nil, ParseError, "Request body is empty after trimming", nil),
			},
		}, nil
	}

	// Check if it's an array (batch request)
	if body[0] == '[' {
		return e.handleBatch(body)
	}

	// Single request
	return e.handleSingle(body)
}

// handleSingle processes a single JSON-RPC request.
func (e *Endpoint) handleSingle(body []byte) (endpoint.Renderer, error) {
	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		return &jsonrpcRenderer{
			responses: []Response{
				newErrorResponse(nil, ParseError, "Parse error", err.Error()),
			},
		}, nil
	}

	// Validate JSON-RPC version
	if req.JSONRPC != "2.0" {
		return &jsonrpcRenderer{
			responses: []Response{
				newErrorResponse(req.ID, InvalidRequest, "Invalid JSON-RPC version", nil),
			},
		}, nil
	}

	// Validate method name
	if req.Method == "" {
		return &jsonrpcRenderer{
			responses: []Response{
				newErrorResponse(req.ID, InvalidRequest, "Method name is required", nil),
			},
		}, nil
	}

	// Execute the method
	resp := e.executeMethod(req)
	return &jsonrpcRenderer{responses: []Response{resp}}, nil
}

// handleBatch processes a batch of JSON-RPC requests.
func (e *Endpoint) handleBatch(body []byte) (endpoint.Renderer, error) {
	var requests []Request
	if err := json.Unmarshal(body, &requests); err != nil {
		return &jsonrpcRenderer{
			responses: []Response{
				newErrorResponse(nil, ParseError, "Parse error", err.Error()),
			},
		}, nil
	}

	// Empty batch is an error
	if len(requests) == 0 {
		return &jsonrpcRenderer{
			responses: []Response{
				newErrorResponse(nil, InvalidRequest, "Invalid batch: empty array", nil),
			},
		}, nil
	}

	// Process each request in the batch
	var responses []Response
	for _, req := range requests {
		// Validate JSON-RPC version
		if req.JSONRPC != "2.0" {
			responses = append(responses, newErrorResponse(req.ID, InvalidRequest, "Invalid JSON-RPC version", nil))
			continue
		}

		// Validate method name
		if req.Method == "" {
			responses = append(responses, newErrorResponse(req.ID, InvalidRequest, "Method name is required", nil))
			continue
		}

		// Execute the method
		resp := e.executeMethod(req)
		// Only add response if it has an ID (not a notification)
		if req.ID != nil {
			responses = append(responses, resp)
		}
	}

	return &jsonrpcRenderer{responses: responses}, nil
}

// executeMethod executes a registered method and returns the response.
func (e *Endpoint) executeMethod(req Request) Response {
	// Find the method
	methodFunc, ok := e.methods[req.Method]
	if !ok {
		return newErrorResponse(req.ID, MethodNotFound, fmt.Sprintf("Method not found: %s", req.Method), nil)
	}

	// Call the method
	result, err := methodFunc(context.Background(), req.Params)
	if err != nil {
		return e.mapError(req.ID, err)
	}

	return Response{
		JSONRPC: "2.0",
		Result:  result,
		ID:      req.ID,
	}
}

// mapError maps a Go error to a JSON-RPC response.
func (e *Endpoint) mapError(id *json.RawMessage, err error) Response {
	// Check if it's already a JSON-RPC error
	var rpcErr *Error
	if errors.As(err, &rpcErr) {
		return Response{
			JSONRPC: "2.0",
			Error:   rpcErr,
			ID:      id,
		}
	}

	// Map to internal error
	return newErrorResponse(id, InternalError, "Internal error", nil)
}

// newErrorResponse creates a new error response.
func newErrorResponse(id *json.RawMessage, code int, message string, data any) Response {
	return Response{
		JSONRPC: "2.0",
		Error: &Error{
			Code:    code,
			Message: message,
			Data:    data,
		},
		ID: id,
	}
}

// jsonrpcRenderer renders JSON-RPC responses.
type jsonrpcRenderer struct {
	responses []Response
}

// Render implements endpoint.Renderer.
func (jr *jsonrpcRenderer) Render(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")

	// Check if this is a notification (no ID in single request)
	// A notification has no ID AND no error (successful notification)
	if len(jr.responses) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return nil
	}

	// For single requests, check if it's a notification (no ID and no error)
	if len(jr.responses) == 1 && jr.responses[0].ID == nil && jr.responses[0].Error == nil {
		w.WriteHeader(http.StatusNoContent)
		return nil
	}

	// Encode response to buffer to calculate Content-Length
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)

	if len(jr.responses) == 1 {
		if err := enc.Encode(jr.responses[0]); err != nil {
			return err
		}
	} else {
		if err := enc.Encode(jr.responses); err != nil {
			return err
		}
	}

	// Set Content-Length header
	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))

	// Return 200 OK with the response
	w.WriteHeader(http.StatusOK)

	// Write the response body
	_, err := w.Write(buf.Bytes())
	return err
}

// Register registers a receiver's exported methods as JSON-RPC methods.
//
// The namespace parameter is prepended to method names with a dot separator.
// If namespace is empty, methods are registered with their original names.
//
// Example:
//
//	type Math struct{}
//	func (m *Math) Add(ctx context.Context, a, b int) (int, error) { ... }
//
//	e.Register("math", &Math{})  // registers "math.Add"
//	e.Register("", &Math{})      // registers "Add"
func (e *Endpoint) Register(namespace string, receiver interface{}) {
	recvVal := reflect.ValueOf(receiver)
	recvType := recvVal.Type()

	// Ensure we have a pointer type for method access
	if recvType.Kind() != reflect.Ptr {
		recvVal = recvVal.Addr()
		recvType = recvVal.Type()
	}

	// Register each exported method
	for i := 0; i < recvType.NumMethod(); i++ {
		method := recvType.Method(i)

		// Skip unexported methods
		if method.PkgPath != "" {
			continue
		}

		// Build method name
		methodName := method.Name
		if namespace != "" {
			methodName = namespace + "." + methodName
		}

		// Create method function
		methodFunc := e.createMethodFunc(recvVal, method)

		// Store method
		e.methods[methodName] = methodFunc
	}
}

// createMethodFunc creates a function that calls the given method with JSON-RPC params.
func (e *Endpoint) createMethodFunc(recvPtr reflect.Value, method reflect.Method) methodFunc {
	methodType := method.Type

	return func(ctx context.Context, params json.RawMessage) (any, error) {
		numIn := methodType.NumIn()

		// Build argument list
		args := make([]reflect.Value, numIn)
		args[0] = recvPtr // First argument is the receiver

		// Second argument is context.Context if present
		startIdx := 1
		if numIn > 1 {
			argType := methodType.In(1)
			if argType == reflect.TypeOf((*context.Context)(nil)).Elem() {
				args[1] = reflect.ValueOf(ctx)
				startIdx = 2
			}
		}

		// Decode remaining parameters if provided
		if len(params) > 0 && numIn > startIdx {
			if err := decodeParams(params, methodType, startIdx, args); err != nil {
				return nil, err
			}
		}

		// Get the method from the pointer and call it
		methodValue := recvPtr.MethodByName(method.Name)
		results := methodValue.Call(args[1:]) // Skip receiver, it's already bound

		// Process results
		return processResults(results)
	}
}

// decodeParams decodes JSON-RPC params into method arguments.
func decodeParams(params json.RawMessage, methodType reflect.Type, startIdx int, args []reflect.Value) error {
	// Handle positional params (array)
	if len(params) > 0 && params[0] == '[' {
		var posParams []json.RawMessage
		if err := json.Unmarshal(params, &posParams); err != nil {
			return NewError(InvalidParams, "Failed to parse positional parameters", err.Error())
		}

		for i, p := range posParams {
			argIdx := startIdx + i
			if argIdx >= methodType.NumIn() {
				return NewError(InvalidParams, "Too many parameters", nil)
			}
			argType := methodType.In(argIdx)
			argVal := reflect.New(argType)
			if err := json.Unmarshal(p, argVal.Interface()); err != nil {
				return NewError(InvalidParams, fmt.Sprintf("Failed to decode parameter %d", i), err.Error())
			}
			args[argIdx] = argVal.Elem()
		}
		return nil
	}

	// Handle named params (object)
	if len(params) > 0 && params[0] == '{' {
		// For named params, we expect a single struct parameter
		if methodType.NumIn() != startIdx+1 {
			return NewError(InvalidParams, "Named parameters require a single struct parameter", nil)
		}
		argType := methodType.In(startIdx)
		argVal := reflect.New(argType)
		if err := json.Unmarshal(params, argVal.Interface()); err != nil {
			return NewError(InvalidParams, "Failed to decode named parameters", err.Error())
		}
		args[startIdx] = argVal.Elem()
		return nil
	}

	return nil
}

// processResults processes the return values from a method call.
func processResults(results []reflect.Value) (any, error) {
	if len(results) == 0 {
		return nil, nil
	}

	// Check for error return (last value if there are 2+ returns)
	if len(results) >= 2 {
		lastResult := results[len(results)-1]
		if !lastResult.IsNil() {
			errVal := lastResult.Interface()
			if err, ok := errVal.(error); ok {
				// Return error and nil result
				if results[0].IsValid() && isNonNil(results[0]) {
					return results[0].Interface(), err
				}
				return nil, err
			}
		}
	}

	// Return the first result
	if results[0].IsValid() && isNonNil(results[0]) {
		return results[0].Interface(), nil
	}
	return nil, nil
}

// isNonNil checks if a value is non-nil (safe for all types)
func isNonNil(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return !v.IsNil()
	default:
		return true
	}
}

// trimSpace removes leading/trailing whitespace from byte slice.
func trimSpace(s []byte) []byte {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}

// normalizeMethodName normalizes a method name for lookup (case-insensitive).
func normalizeMethodName(name string) string {
	return strings.ToLower(name)
}
