// Package jsonrpc provides a JSON-RPC 2.0 server implementation.
//
// The package integrates with the oneserve endpoint architecture, allowing
// JSON-RPC methods to be registered and served over HTTP with support for
// processors, authentication, and logging.
//
// # Basic Usage
//
//	package main
//
//	import (
//	    "context"
//	    "encoding/json"
//	    "log"
//	    "net/http"
//
//	    "github.com/mnehpets/oneserve/endpoint"
//	    "github.com/mnehpets/oneserve/jsonrpc"
//	)
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
//	    log.Fatal(http.ListenAndServe(":8080", nil))
//	}
//
// # Method Registration
//
// Methods are registered on a struct receiver. The method name becomes the
// RPC method name, optionally prefixed with a namespace:
//
//	e.Register("math", &MathMethods{})
//	// -> RPC method: "math.Add"
//
//	e.Register("", &Methods{})  // empty namespace
//	// -> RPC method: "Add" (from Foobar -> foobar -> Foobar conversion)
//
// Methods must:
//   - Accept context.Context as first parameter
//   - Return at most two values: result and error
//
// # Error Codes
//
// The package maps errors to standard JSON-RPC error codes:
//   - -32700: Parse error
//   - -32600: Invalid request
//   - -32601: Method not found
//   - -32602: Invalid params
//   - -32603: Internal error
//
// Custom error codes can be returned using JSONRPCError.
package jsonrpc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"

	"github.com/mnehpets/oneserve/endpoint"
)

const (
	ParseError     = -32700
	InvalidRequest = -32600
	MethodNotFound = -32601
	InvalidParams  = -32602
	InternalError  = -32603
)

type JSONRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *JSONRPCError) Error() string {
	return e.Message
}

type JSONRPCEndpoint struct {
	methods map[string]reflect.Value
}

func NewEndpoint() *JSONRPCEndpoint {
	return &JSONRPCEndpoint{
		methods: make(map[string]reflect.Value),
	}
}

func (e *JSONRPCEndpoint) Register(namespace string, receiver interface{}) {
	receiverType := reflect.TypeOf(receiver)
	receiverValue := reflect.ValueOf(receiver)

	for i := 0; i < receiverType.NumMethod(); i++ {
		method := receiverType.Method(i)
		if method.PkgPath != "" {
			continue
		}

		if method.Type.NumIn() < 2 {
			continue
		}

		if method.Type.In(1) != reflect.TypeOf((*context.Context)(nil)).Elem() {
			continue
		}

		var methodName string
		if namespace == "" {
			methodName = toLowerFirst(method.Name)
		} else {
			methodName = namespace + "." + toLowerFirst(method.Name)
		}

		e.methods[methodName] = receiverValue.Method(i)
	}
}

func toLowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

type rpcParams struct {
	Body []byte `body:""`
}

func (e *JSONRPCEndpoint) Endpoint(w http.ResponseWriter, r *http.Request, params rpcParams) (endpoint.Renderer, error) {
	if r.Method != http.MethodPost {
		return nil, endpoint.Error(http.StatusMethodNotAllowed, "method not allowed", nil)
	}

	ct := r.Header.Get("Content-Type")
	if ct != "" && !isJSONContentType(ct) {
		return nil, endpoint.Error(http.StatusUnsupportedMediaType, "content-type must be application/json", nil)
	}

	return e.handleBody(w, r, params.Body)
}

func isJSONContentType(ct string) bool {
	ct = strings.TrimSpace(strings.ToLower(ct))
	return ct == "application/json" || strings.HasPrefix(ct, "application/json")
}

func (e *JSONRPCEndpoint) handleBody(w http.ResponseWriter, r *http.Request, body []byte) (endpoint.Renderer, error) {
	if len(body) == 0 {
		return e.renderError(InvalidRequest, "Empty request body")
	}

	var batch []json.RawMessage
	isBatch := json.Unmarshal(body, &batch) == nil

	if isBatch && len(batch) == 0 {
		return e.renderError(InvalidRequest, "Empty batch request")
	}

	if isBatch {
		responses := make([]json.RawMessage, 0, len(batch))
		for _, reqBody := range batch {
			resp := e.processRequest(r.Context(), reqBody)
			if resp != nil {
				responses = append(responses, resp)
			}
		}
		if len(responses) == 0 {
			return &endpoint.NoContentRenderer{}, nil
		}
		return &jsonrpcRenderer{data: responses, isBatch: true}, nil
	}

	resp := e.processRequest(r.Context(), body)
	if resp == nil {
		return &endpoint.NoContentRenderer{}, nil
	}
	return &jsonrpcRenderer{data: []json.RawMessage{resp}, isBatch: false}, nil
}

func (e *JSONRPCEndpoint) processRequest(ctx context.Context, body []byte) json.RawMessage {
	var req struct {
		JSONRPC string          `json:"jsonrpc"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params,omitempty"`
		ID      json.RawMessage `json:"id,omitempty"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		return e.buildErrorResponse(nil, ParseError, "Parse error")
	}

	if req.JSONRPC != "2.0" || req.Method == "" {
		return e.buildErrorResponse(nil, InvalidRequest, "Invalid Request")
	}

	method, ok := e.methods[req.Method]
	if !ok {
		return e.buildErrorResponse(nil, MethodNotFound, "Method not found")
	}

	result, err := e.callMethod(ctx, method, req.Params)
	if err != nil {
		var rpcErr *JSONRPCError
		if errors.As(err, &rpcErr) {
			return e.buildErrorResponse(nil, rpcErr.Code, rpcErr.Message)
		}
		return e.buildErrorResponse(nil, InternalError, "Internal error")
	}

	idIsNull := string(req.ID) == "null"
	idEmpty := len(req.ID) == 0
	if idEmpty || idIsNull {
		return nil
	}

	return e.buildSuccessResponse(req.ID, result)
}

func (e *JSONRPCEndpoint) callMethod(ctx context.Context, method reflect.Value, params json.RawMessage) (json.RawMessage, error) {
	methodType := method.Type()

	numArgs := methodType.NumIn()
	numReturns := methodType.NumOut()

	var args []reflect.Value
	args = append(args, reflect.ValueOf(ctx))

	if numArgs > 1 && len(params) > 0 {
		paramType := methodType.In(1)
		paramKind := paramType.Kind()

		if paramKind == reflect.Slice {
			sliceType := paramType.Elem()
			sliceValue := reflect.MakeSlice(paramType, 0, 0)

			var paramValues []json.RawMessage
			if err := json.Unmarshal(params, &paramValues); err == nil {
				for _, pv := range paramValues {
					elemValue := reflect.New(sliceType.Elem()).Interface()
					if err := json.Unmarshal(pv, elemValue); err != nil {
						return nil, &JSONRPCError{Code: InvalidParams, Message: err.Error()}
					}
					sliceValue = reflect.Append(sliceValue, reflect.Indirect(reflect.ValueOf(elemValue)))
				}
				args = append(args, sliceValue)
			} else {
				return nil, &JSONRPCError{Code: InvalidParams, Message: err.Error()}
			}
		} else if paramKind == reflect.Struct {
			paramValue := reflect.New(paramType).Interface()
			if err := json.Unmarshal(params, paramValue); err != nil {
				var paramValues []json.RawMessage
				if err2 := json.Unmarshal(params, &paramValues); err2 == nil {
					fields := reflect.VisibleFields(paramType)
					if len(paramValues) >= len(fields) {
						for j := 0; j < len(fields) && j < len(paramValues); j++ {
							field := fields[j]
							fieldValue := reflect.New(field.Type).Interface()
							if err := json.Unmarshal(paramValues[j], fieldValue); err != nil {
								return nil, &JSONRPCError{Code: InvalidParams, Message: err.Error()}
							}
							reflect.ValueOf(paramValue).Elem().FieldByIndex([]int{j}).Set(reflect.Indirect(reflect.ValueOf(fieldValue)))
						}
					} else {
						return nil, &JSONRPCError{Code: InvalidParams, Message: "Not enough parameters for struct"}
					}
				} else {
					return nil, &JSONRPCError{Code: InvalidParams, Message: err.Error()}
				}
			}
			args = append(args, reflect.Indirect(reflect.ValueOf(paramValue)))
		} else {
			var paramValues []json.RawMessage
			if err := json.Unmarshal(params, &paramValues); err == nil {
				if len(paramValues) >= numArgs-1 {
					for j := 0; j < numArgs-1 && j < len(paramValues); j++ {
						elemType := paramType
						elemValue := reflect.New(elemType).Interface()
						if err := json.Unmarshal(paramValues[j], elemValue); err != nil {
							return nil, &JSONRPCError{Code: InvalidParams, Message: err.Error()}
						}
						args = append(args, reflect.Indirect(reflect.ValueOf(elemValue)))
					}
				} else {
					return nil, &JSONRPCError{Code: InvalidParams, Message: "Not enough parameters"}
				}
			} else {
				paramValue := reflect.New(paramType).Interface()
				if err := json.Unmarshal(params, paramValue); err != nil {
					return nil, &JSONRPCError{Code: InvalidParams, Message: err.Error()}
				}
				args = append(args, reflect.Indirect(reflect.ValueOf(paramValue)))
			}
		}
	}

	results := method.Call(args)

	if numReturns > 1 {
		errVal := results[1].Interface()
		if errVal != nil {
			return nil, errVal.(error)
		}
	}

	if numReturns > 0 {
		resultVal := results[0].Interface()
		if resultVal == nil {
			return nil, nil
		}
		data, err := json.Marshal(resultVal)
		if err != nil {
			return nil, &JSONRPCError{Code: InternalError, Message: "Failed to marshal result"}
		}
		return data, nil
	}

	return nil, nil
}

func (e *JSONRPCEndpoint) buildSuccessResponse(id json.RawMessage, result json.RawMessage) json.RawMessage {
	resp := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result,omitempty"`
	}{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
	data, _ := json.Marshal(resp)
	return data
}

func (e *JSONRPCEndpoint) buildErrorResponse(id json.RawMessage, code int, message string) json.RawMessage {
	resp := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{
		JSONRPC: "2.0",
		ID:      id,
	}
	resp.Error.Code = code
	resp.Error.Message = message
	data, _ := json.Marshal(resp)
	return data
}

func (e *JSONRPCEndpoint) renderError(code int, message string) (endpoint.Renderer, error) {
	data := e.buildErrorResponse(nil, code, message)
	return &jsonrpcRenderer{data: []json.RawMessage{data}, isBatch: false}, nil
}

type jsonrpcRenderer struct {
	data    []json.RawMessage
	isBatch bool
}

func (r *jsonrpcRenderer) Render(w http.ResponseWriter, _ *http.Request) error {
	w.Header().Set("Content-Type", "application/json")
	if r.isBatch {
		_, err := io.WriteString(w, "[")
		if err != nil {
			return err
		}
		for i, item := range r.data {
			if i > 0 {
				_, err = io.WriteString(w, ",")
				if err != nil {
					return err
				}
			}
			_, err = w.Write(item)
			if err != nil {
				return err
			}
		}
		_, err = io.WriteString(w, "]")
		return err
	}
	if len(r.data) == 0 {
		return nil
	}
	_, err := w.Write(r.data[0])
	return err
}
