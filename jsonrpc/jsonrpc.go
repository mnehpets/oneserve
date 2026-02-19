package jsonrpc

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"sync"

	"github.com/mnehpets/oneserve/endpoint"
)

const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
)

// JSONRPCError represents a JSON-RPC 2.0 error response.
type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Error implements the error interface.
func (e *JSONRPCError) Error() string {
	return e.Message
}

// NewParseError creates a parse error (-32700).
// Returned when invalid JSON was received by the server.
func NewParseError(message string) *JSONRPCError {
	return &JSONRPCError{Code: CodeParseError, Message: message}
}

// NewInvalidRequestError creates an invalid request error (-32600).
// Returned when the JSON sent is not a valid Request object.
func NewInvalidRequestError(message string) *JSONRPCError {
	return &JSONRPCError{Code: CodeInvalidRequest, Message: message}
}

// NewMethodNotFoundError creates a method not found error (-32601).
// Returned when the method does not exist or is not available.
func NewMethodNotFoundError(message string) *JSONRPCError {
	return &JSONRPCError{Code: CodeMethodNotFound, Message: message}
}

// NewInvalidParamsError creates an invalid params error (-32602).
// Returned when invalid method parameter(s) are provided.
func NewInvalidParamsError(message string) *JSONRPCError {
	return &JSONRPCError{Code: CodeInvalidParams, Message: message}
}

// NewInternalError creates an internal error (-32603).
// Returned for internal JSON-RPC errors.
func NewInternalError(message string) *JSONRPCError {
	return &JSONRPCError{Code: CodeInternalError, Message: message}
}

// rpcMethod holds reflection data for a registered RPC method.
type rpcMethod struct {
	receiver   reflect.Value
	method     reflect.Method
	paramTypes []reflect.Type
	hasContext bool
	returnsVal bool
	returnsErr bool
}

// call invokes the method with the given context and parameters.
// Panics are recovered and converted to InternalError.
func (m *rpcMethod) call(ctx context.Context, params json.RawMessage) (result interface{}, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = NewInternalError("internal error")
		}
	}()

	// Build argument list: receiver is always first.
	args := make([]reflect.Value, 0, 1+len(m.paramTypes))
	args = append(args, m.receiver)

	if m.hasContext {
		args = append(args, reflect.ValueOf(ctx))
	}

	if len(m.paramTypes) > 0 {
		if params == nil {
			params = json.RawMessage("[]")
		}

		// Try to parse params as array first, then as single value.
		// JSON-RPC allows: "params": [1, 2] or "params": {"a": 1}
		var paramList []json.RawMessage
		if err := json.Unmarshal(params, &paramList); err != nil {
			// Not an array - try as single value.
			var singleParam json.RawMessage
			if err2 := json.Unmarshal(params, &singleParam); err2 == nil {
				paramList = []json.RawMessage{singleParam}
			} else {
				return nil, NewInvalidParamsError("invalid params")
			}
		}

		if len(paramList) != len(m.paramTypes) {
			return nil, NewInvalidParamsError("invalid number of params")
		}

		// Unmarshal each param to its expected type.
		for i, rawParam := range paramList {
			param := reflect.New(m.paramTypes[i])
			if err := json.Unmarshal(rawParam, param.Interface()); err != nil {
				return nil, NewInvalidParamsError("invalid param " + string(rune('0'+i)))
			}
			args = append(args, param.Elem())
		}
	}

	results := m.method.Func.Call(args)

	var retResult interface{}
	var retErr error

	// Extract return values based on method signature.
	if m.returnsVal && len(results) > 0 {
		retResult = results[0].Interface()
	}
	if m.returnsErr && len(results) > 0 {
		if !results[len(results)-1].IsNil() {
			retErr = results[len(results)-1].Interface().(error)
		}
	}

	return retResult, retErr
}

// JSONRPCEndpoint is a registry for JSON-RPC methods.
// Use endpoint.Handler(e.Endpoint, processors...) to create an http.Handler.
type JSONRPCEndpoint struct {
	mu      sync.RWMutex
	methods map[string]*rpcMethod
}

// NewEndpoint creates a new JSON-RPC method registry.
func NewEndpoint() *JSONRPCEndpoint {
	return &JSONRPCEndpoint{
		methods: make(map[string]*rpcMethod),
	}
}

// Register adds methods from a receiver struct to the endpoint.
// The namespace prefixes all method names (e.g., "math" + "Add" -> "math.Add").
// Use empty string for no namespace (method names used directly).
// Only exported methods with valid signatures are registered.
func (e *JSONRPCEndpoint) Register(namespace string, receiver interface{}) {
	val := reflect.ValueOf(receiver)
	typ := val.Type()

	for i := 0; i < val.NumMethod(); i++ {
		method := typ.Method(i)
		if !method.IsExported() {
			continue
		}

		name := method.Name
		if namespace != "" {
			name = namespace + "." + name
		}

		handler := parseMethod(val, method)
		// parseMethod returns nil for invalid signatures (e.g., 3+ return values)
		if handler != nil {
			e.mu.Lock()
			e.methods[name] = handler
			e.mu.Unlock()
		}
	}
}

// rpcParams captures the raw JSON-RPC request body.
// We defer parsing until inside the endpoint handler,
// as json-rpc requires different handling of json parsing
// errors than the default oneserve json body parser.
type rpcParams struct {
	Body []byte `body:""`
}

// Endpoint is the endpoint function that processes JSON-RPC requests.
// Pass to endpoint.Handler() to create an http.Handler.
func (e *JSONRPCEndpoint) Endpoint(w http.ResponseWriter, r *http.Request, params rpcParams) (endpoint.Renderer, error) {
	if r.Method != http.MethodPost {
		return nil, endpoint.Error(http.StatusMethodNotAllowed, "JSON-RPC requires POST method", nil)
	}

	return e.handleBody(r.Context(), params.Body)
}

// handleBody processes the JSON-RPC request body and returns a renderer.
func (e *JSONRPCEndpoint) handleBody(ctx context.Context, body []byte) (endpoint.Renderer, error) {
	var reqs []json.RawMessage
	var single bool

	// Peek at first byte to distinguish batch vs single request.
	if len(body) > 0 && body[0] == '[' {
		if err := json.Unmarshal(body, &reqs); err != nil {
			return &jsonrpcRenderer{err: NewParseError("parse error")}, nil
		}
	} else {
		reqs = []json.RawMessage{body}
		single = true
	}

	if len(reqs) == 0 {
		return &jsonrpcRenderer{err: NewInvalidRequestError("invalid request")}, nil
	}

	responses := make([]response, 0, len(reqs))
	for _, rawReq := range reqs {
		var req request
		if err := json.Unmarshal(rawReq, &req); err != nil {
			responses = append(responses, response{
				JSONRPC: "2.0",
				Error:   NewParseError("parse error"),
				ID:      nil,
			})
			continue
		}

		if req.JSONRPC != "2.0" {
			responses = append(responses, response{
				JSONRPC: "2.0",
				Error:   NewInvalidRequestError("invalid request"),
				ID:      req.ID,
			})
			continue
		}

		if req.Method == "" {
			responses = append(responses, response{
				JSONRPC: "2.0",
				Error:   NewInvalidRequestError("method required"),
				ID:      req.ID,
			})
			continue
		}

		// Notification: no id means no response expected.
		if req.ID == nil {
			e.invokeMethod(ctx, req.Method, req.Params)
			continue
		}

		result, err := e.invokeMethod(ctx, req.Method, req.Params)
		resp := response{
			JSONRPC: "2.0",
			ID:      req.ID,
		}
		if err != nil {
			resp.Error = mapError(err)
		} else {
			resp.Result = result
		}
		responses = append(responses, resp)
	}

	// No responses means all requests were notifications.
	if len(responses) == 0 {
		return &jsonrpcRenderer{noContent: true}, nil
	}

	return &jsonrpcRenderer{responses: responses, single: single}, nil
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	ID      interface{}     `json:"id"`
}

type response struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   interface{} `json:"error,omitempty"`
	ID      interface{} `json:"id,omitempty"`
}

// jsonrpcRenderer renders JSON-RPC responses.
type jsonrpcRenderer struct {
	responses []response
	single    bool
	noContent bool
	err       *JSONRPCError
}

func (r *jsonrpcRenderer) Render(w http.ResponseWriter, req *http.Request) error {
	w.Header().Set("Content-Type", "application/json")

	if r.err != nil {
		w.WriteHeader(http.StatusOK)
		return json.NewEncoder(w).Encode(response{
			JSONRPC: "2.0",
			Error:   r.err,
			ID:      nil,
		})
	}

	if r.noContent {
		w.WriteHeader(http.StatusNoContent)
		return nil
	}

	w.WriteHeader(http.StatusOK)
	if r.single {
		return json.NewEncoder(w).Encode(r.responses[0])
	}
	return json.NewEncoder(w).Encode(r.responses)
}

// parseMethod extracts method signature information via reflection.
// Valid signatures:
//   - func(ctx context.Context, params...) (result, error)
//   - func(ctx context.Context, params...) error
//   - func(ctx context.Context, params...) result
//   - func(params...) (result, error)
//   - func(params...) error
//   - func(params...) result
//   - func(ctx context.Context)
//   - func()
//
// Returns nil for invalid signatures.
func parseMethod(receiver reflect.Value, method reflect.Method) *rpcMethod {
	ft := method.Func.Type()
	numIn := ft.NumIn()

	// First parameter is always the receiver, skip it.
	// Check if second parameter is context.Context.
	hasContext := false
	paramStart := 1
	if numIn >= 2 && ft.In(1) == reflect.TypeOf((*context.Context)(nil)).Elem() {
		hasContext = true
		paramStart = 2
	}

	paramTypes := make([]reflect.Type, 0, numIn-paramStart)
	for i := paramStart; i < numIn; i++ {
		paramTypes = append(paramTypes, ft.In(i))
	}

	returnsVal := false
	returnsErr := false

	switch ft.NumOut() {
	case 0:
		// No return values - valid for notifications.
	case 1:
		if ft.Out(0) == reflect.TypeOf((*error)(nil)).Elem() {
			returnsErr = true
		} else {
			returnsVal = true
		}
	case 2:
		// Two returns must be (result, error).
		returnsVal = true
		returnsErr = true
		if ft.Out(1) != reflect.TypeOf((*error)(nil)).Elem() {
			return nil
		}
	default:
		// More than 2 return values is invalid.
		return nil
	}

	return &rpcMethod{
		receiver:   receiver,
		method:     method,
		paramTypes: paramTypes,
		hasContext: hasContext,
		returnsVal: returnsVal,
		returnsErr: returnsErr,
	}
}

// invokeMethod looks up and calls a registered method by name.
func (e *JSONRPCEndpoint) invokeMethod(ctx context.Context, name string, params json.RawMessage) (interface{}, error) {
	e.mu.RLock()
	method, ok := e.methods[name]
	e.mu.RUnlock()

	if !ok {
		return nil, NewMethodNotFoundError("method not found: " + name)
	}

	return method.call(ctx, params)
}

// mapError converts any error to a JSON-RPC error.
// JSONRPCError types preserve their code; other errors become InternalError.
func mapError(err error) interface{} {
	if rpcErr, ok := err.(*JSONRPCError); ok {
		return rpcErr
	}
	return &JSONRPCError{
		Code:    CodeInternalError,
		Message: err.Error(),
	}
}
