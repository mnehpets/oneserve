package jsonrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mnehpets/oneserve/endpoint"
)

func serveRPC(e *JSONRPCEndpoint, processors ...endpoint.Processor) http.Handler {
	return endpoint.Handler(e.Endpoint, processors...)
}

func TestHandlerImplementsHTTPHandler(t *testing.T) {
	e := NewEndpoint()
	_ = e // JSONRPCEndpoint is not itself an http.Handler - use endpoint.Handler(e.Endpoint)
}

func TestPOSTOnlyEnforcement(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &testMethods{})

	tests := []struct {
		method   string
		wantCode int
	}{
		{http.MethodGet, http.StatusMethodNotAllowed},
		{http.MethodPut, http.StatusMethodNotAllowed},
		{http.MethodDelete, http.StatusMethodNotAllowed},
		{http.MethodPost, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/", bytes.NewReader([]byte(`{"jsonrpc":"2.0","method":"test.Echo","params":["hello"],"id":1}`)))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			serveRPC(e).ServeHTTP(rec, req)
			if rec.Code != tt.wantCode {
				t.Errorf("got status %d, want %d", rec.Code, tt.wantCode)
			}
		})
	}
}

func TestMethodRegistrationWithNamespace(t *testing.T) {
	e := NewEndpoint()
	e.Register("math", &mathMethods{})

	body := `{"jsonrpc":"2.0","method":"math.Add","params":[2,3],"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["result"].(float64) != 5 {
		t.Errorf("got result %v, want 5", resp["result"])
	}
}

func TestMethodRegistrationWithoutNamespace(t *testing.T) {
	e := NewEndpoint()
	e.Register("", &mathMethods{})

	body := `{"jsonrpc":"2.0","method":"Add","params":[2,3],"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["result"].(float64) != 5 {
		t.Errorf("got result %v, want 5", resp["result"])
	}
}

func TestSingleRequestSuccess(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &testMethods{})

	body := `{"jsonrpc":"2.0","method":"test.Echo","params":["hello"],"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["result"] != "hello" {
		t.Errorf("got result %v, want 'hello'", resp["result"])
	}
}

func TestNotificationHandling(t *testing.T) {
	e := NewEndpoint()
	methods := &notifyMethods{called: false}
	e.Register("notify", methods)

	body := `{"jsonrpc":"2.0","method":"notify.Ping","params":[]}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	if !methods.called {
		t.Error("notification method was not called")
	}

	if rec.Code != http.StatusNoContent {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestBatchRequestHandling(t *testing.T) {
	e := NewEndpoint()
	e.Register("math", &mathMethods{})

	body := `[
		{"jsonrpc":"2.0","method":"math.Add","params":[1,2],"id":1},
		{"jsonrpc":"2.0","method":"math.Add","params":[3,4],"id":2}
	]`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	var resp []map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if len(resp) != 2 {
		t.Fatalf("got %d responses, want 2", len(resp))
	}

	if resp[0]["result"].(float64) != 3 {
		t.Errorf("got result %v, want 3", resp[0]["result"])
	}
	if resp[1]["result"].(float64) != 7 {
		t.Errorf("got result %v, want 7", resp[1]["result"])
	}
}

func TestEmptyBatchRequest(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &testMethods{})

	body := `[]`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["error"] == nil {
		t.Error("expected error response for empty batch")
	}
}

func TestParseError(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &testMethods{})

	body := `{"jsonrpc":"2.0","method":"test.Echo","params":[invalid json`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	errObj := resp["error"].(map[string]interface{})
	if int(errObj["code"].(float64)) != CodeParseError {
		t.Errorf("got error code %v, want %d", errObj["code"], CodeParseError)
	}
}

func TestMethodNotFound(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &testMethods{})

	body := `{"jsonrpc":"2.0","method":"test.Nonexistent","params":[],"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	errObj := resp["error"].(map[string]interface{})
	if int(errObj["code"].(float64)) != CodeMethodNotFound {
		t.Errorf("got error code %v, want %d", errObj["code"], CodeMethodNotFound)
	}
}

func TestInvalidParams(t *testing.T) {
	e := NewEndpoint()
	e.Register("math", &mathMethods{})

	body := `{"jsonrpc":"2.0","method":"math.Add","params":["not","numbers"],"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if resp["error"] == nil {
		t.Error("expected error response for invalid params")
	}
}

func TestCustomErrorCodes(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &testMethods{})

	body := `{"jsonrpc":"2.0","method":"test.Fail","params":[],"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	errObj := resp["error"].(map[string]interface{})
	if int(errObj["code"].(float64)) != -1000 {
		t.Errorf("got error code %v, want -1000", errObj["code"])
	}
}

func TestProcessorChainExecution(t *testing.T) {
	executed := false
	processor := endpoint.ProcessorFunc(func(w http.ResponseWriter, r *http.Request, next func(w http.ResponseWriter, r *http.Request) error) error {
		executed = true
		return next(w, r)
	})

	e := NewEndpoint()
	e.Register("test", &testMethods{})

	body := `{"jsonrpc":"2.0","method":"test.Echo","params":["hello"],"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e, processor).ServeHTTP(rec, req)

	if !executed {
		t.Error("processor was not executed")
	}

	if rec.Code != http.StatusOK {
		t.Errorf("got status %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestProcessorErrorReturnsHTTPError(t *testing.T) {
	processor := endpoint.ProcessorFunc(func(w http.ResponseWriter, r *http.Request, next func(w http.ResponseWriter, r *http.Request) error) error {
		return endpoint.Error(http.StatusForbidden, "access denied", nil)
	})

	e := NewEndpoint()
	e.Register("test", &testMethods{})

	body := `{"jsonrpc":"2.0","method":"test.Echo","params":["hello"],"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e, processor).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestContextPropagationThroughProcessors(t *testing.T) {
	ctxKey := struct{}{}
	var gotValue string

	processor := endpoint.ProcessorFunc(func(w http.ResponseWriter, r *http.Request, next func(w http.ResponseWriter, r *http.Request) error) error {
		ctx := context.WithValue(r.Context(), ctxKey, "test-value")
		return next(w, r.WithContext(ctx))
	})

	methods := &contextMethods{ctxKey: ctxKey, getValue: func(v string) { gotValue = v }}
	e := NewEndpoint()
	e.Register("ctx", methods)

	body := `{"jsonrpc":"2.0","method":"ctx.GetValue","params":[],"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e, processor).ServeHTTP(rec, req)

	if gotValue != "test-value" {
		t.Errorf("got value %q, want 'test-value'", gotValue)
	}
}

func TestErrorConstructors(t *testing.T) {
	tests := []struct {
		name     string
		err      *JSONRPCError
		wantCode int
	}{
		{"ParseError", NewParseError("parse failed"), CodeParseError},
		{"InvalidRequest", NewInvalidRequestError("invalid"), CodeInvalidRequest},
		{"MethodNotFound", NewMethodNotFoundError("not found"), CodeMethodNotFound},
		{"InvalidParams", NewInvalidParamsError("bad params"), CodeInvalidParams},
		{"InternalError", NewInternalError("internal"), CodeInternalError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Code != tt.wantCode {
				t.Errorf("got code %d, want %d", tt.err.Code, tt.wantCode)
			}
			if tt.err.Error() == "" {
				t.Error("error message is empty")
			}
		})
	}
}

func TestAllStandardErrorCodes(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &testMethods{})

	tests := []struct {
		name     string
		body     string
		wantCode int
	}{
		{"ParseError", `{invalid`, CodeParseError},
		{"InvalidRequest", `{"jsonrpc":"1.0","method":"test.Echo","id":1}`, CodeInvalidRequest},
		{"MethodNotFound", `{"jsonrpc":"2.0","method":"unknown","id":1}`, CodeMethodNotFound},
		{"InvalidParams", `{"jsonrpc":"2.0","method":"test.Echo","params":[1,2,3],"id":1}`, CodeInvalidParams},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(tt.body)))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			serveRPC(e).ServeHTTP(rec, req)

			var resp map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to parse response: %v", err)
			}

			errObj := resp["error"].(map[string]interface{})
			if int(errObj["code"].(float64)) != tt.wantCode {
				t.Errorf("got error code %v, want %d", errObj["code"], tt.wantCode)
			}
		})
	}
}

type mathMethods struct{}

func (m *mathMethods) Add(ctx context.Context, a, b int) (int, error) {
	return a + b, nil
}

type testMethods struct{}

func (m *testMethods) Echo(ctx context.Context, s string) (string, error) {
	return s, nil
}

func (m *testMethods) Fail(ctx context.Context) error {
	return &JSONRPCError{Code: -1000, Message: "custom error"}
}

type notifyMethods struct {
	called bool
}

func (m *notifyMethods) Ping(ctx context.Context) {
	m.called = true
}

type contextMethods struct {
	ctxKey   interface{}
	getValue func(string)
}

func (m *contextMethods) GetValue(ctx context.Context) (string, error) {
	v, _ := ctx.Value(m.ctxKey).(string)
	if m.getValue != nil {
		m.getValue(v)
	}
	return v, nil
}

type signatureMethods struct{}

func (m *signatureMethods) NoReturn() {
}

func (m *signatureMethods) ReturnOnly() string {
	return "result"
}

func (m *signatureMethods) ErrorOnly() error {
	return nil
}

func (m *signatureMethods) ResultAndError() (string, error) {
	return "result", nil
}

func (m *signatureMethods) ResultAndErrorFail() (string, error) {
	return "", &JSONRPCError{Code: -100, Message: "failed"}
}

func (m *signatureMethods) NoContext(a, b int) int {
	return a + b
}

func (m *signatureMethods) WithContext(ctx context.Context, s string) string {
	return s
}

type paramTypesMethods struct{}

type Person struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
}

func (m *paramTypesMethods) TakesStruct(p Person) string {
	return p.Name
}

func (m *paramTypesMethods) TakesSlice(items []int) int {
	total := 0
	for _, v := range items {
		total += v
	}
	return total
}

func (m *paramTypesMethods) TakesMap(data map[string]int) int {
	total := 0
	for _, v := range data {
		total += v
	}
	return total
}

func (m *paramTypesMethods) TakesMultiple(a int, b string, c bool) string {
	return b
}

func (m *paramTypesMethods) NoParams() string {
	return "ok"
}

func (m *paramTypesMethods) ReturnsPointer() *Person {
	return &Person{Name: "test", Age: 30}
}

func (m *paramTypesMethods) ReturnsSlice() []int {
	return []int{1, 2, 3}
}

type panicMethods struct{}

func (m *panicMethods) PanicMethod() string {
	panic("something went wrong")
}

func (m *panicMethods) PanicWithContext(ctx context.Context) string {
	panic("panic with context")
}

func TestMethodSignatures(t *testing.T) {
	e := NewEndpoint()
	e.Register("sig", &signatureMethods{})

	tests := []struct {
		name       string
		body       string
		wantResult interface{}
		wantErr    bool
		wantCode   int
	}{
		{"NoReturn", `{"jsonrpc":"2.0","method":"sig.NoReturn","params":[],"id":1}`, nil, false, 0},
		{"ReturnOnly", `{"jsonrpc":"2.0","method":"sig.ReturnOnly","params":[],"id":1}`, "result", false, 0},
		{"ErrorOnly", `{"jsonrpc":"2.0","method":"sig.ErrorOnly","params":[],"id":1}`, nil, false, 0},
		{"ResultAndError", `{"jsonrpc":"2.0","method":"sig.ResultAndError","params":[],"id":1}`, "result", false, 0},
		{"ResultAndErrorFail", `{"jsonrpc":"2.0","method":"sig.ResultAndErrorFail","params":[],"id":1}`, nil, true, -100},
		{"NoContext", `{"jsonrpc":"2.0","method":"sig.NoContext","params":[5,3],"id":1}`, float64(8), false, 0},
		{"WithContext", `{"jsonrpc":"2.0","method":"sig.WithContext","params":["hello"],"id":1}`, "hello", false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(tt.body)))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			serveRPC(e).ServeHTTP(rec, req)

			var resp map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to parse response: %v", err)
			}

			if tt.wantErr {
				if resp["error"] == nil {
					t.Error("expected error, got nil")
				} else if tt.wantCode != 0 {
					errObj := resp["error"].(map[string]interface{})
					if int(errObj["code"].(float64)) != tt.wantCode {
						t.Errorf("got error code %v, want %d", errObj["code"], tt.wantCode)
					}
				}
			} else {
				if resp["error"] != nil {
					t.Errorf("unexpected error: %v", resp["error"])
				}
				if resp["result"] != tt.wantResult {
					t.Errorf("got result %v, want %v", resp["result"], tt.wantResult)
				}
			}
		})
	}
}

func TestParamTypes(t *testing.T) {
	e := NewEndpoint()
	e.Register("params", &paramTypesMethods{})

	tests := []struct {
		name        string
		body        string
		checkResult func(t *testing.T, resp map[string]interface{})
		wantErr     bool
	}{
		{
			"Struct",
			`{"jsonrpc":"2.0","method":"params.TakesStruct","params":[{"name":"Alice","age":30}],"id":1}`,
			func(t *testing.T, resp map[string]interface{}) {
				if resp["result"] != "Alice" {
					t.Errorf("got result %v, want 'Alice'", resp["result"])
				}
			},
			false,
		},
		{
			"Slice",
			`{"jsonrpc":"2.0","method":"params.TakesSlice","params":[[1,2,3,4,5]],"id":1}`,
			func(t *testing.T, resp map[string]interface{}) {
				if resp["result"].(float64) != 15 {
					t.Errorf("got result %v, want 15", resp["result"])
				}
			},
			false,
		},
		{
			"Map",
			`{"jsonrpc":"2.0","method":"params.TakesMap","params":[{"a":1,"b":2,"c":3}],"id":1}`,
			func(t *testing.T, resp map[string]interface{}) {
				if resp["result"].(float64) != 6 {
					t.Errorf("got result %v, want 6", resp["result"])
				}
			},
			false,
		},
		{
			"Multiple",
			`{"jsonrpc":"2.0","method":"params.TakesMultiple","params":[42,"test",true],"id":1}`,
			func(t *testing.T, resp map[string]interface{}) {
				if resp["result"] != "test" {
					t.Errorf("got result %v, want 'test'", resp["result"])
				}
			},
			false,
		},
		{
			"NoParams",
			`{"jsonrpc":"2.0","method":"params.NoParams","params":[],"id":1}`,
			func(t *testing.T, resp map[string]interface{}) {
				if resp["result"] != "ok" {
					t.Errorf("got result %v, want 'ok'", resp["result"])
				}
			},
			false,
		},
		{
			"NoParamsField",
			`{"jsonrpc":"2.0","method":"params.NoParams","id":1}`,
			func(t *testing.T, resp map[string]interface{}) {
				if resp["result"] != "ok" {
					t.Errorf("got result %v, want 'ok'", resp["result"])
				}
			},
			false,
		},
		{
			"ReturnsPointer",
			`{"jsonrpc":"2.0","method":"params.ReturnsPointer","params":[],"id":1}`,
			func(t *testing.T, resp map[string]interface{}) {
				result := resp["result"].(map[string]interface{})
				if result["name"] != "test" {
					t.Errorf("got name %v, want 'test'", result["name"])
				}
			},
			false,
		},
		{
			"ReturnsSlice",
			`{"jsonrpc":"2.0","method":"params.ReturnsSlice","params":[],"id":1}`,
			func(t *testing.T, resp map[string]interface{}) {
				result := resp["result"].([]interface{})
				if len(result) != 3 {
					t.Errorf("got %d items, want 3", len(result))
				}
			},
			false,
		},
		{
			"WrongParamCount",
			`{"jsonrpc":"2.0","method":"params.TakesMultiple","params":[1],"id":1}`,
			nil,
			true,
		},
		{
			"InvalidJSONInParams",
			`{"jsonrpc":"2.0","method":"params.TakesStruct","params":[{invalid}],"id":1}`,
			nil,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(tt.body)))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			serveRPC(e).ServeHTTP(rec, req)

			var resp map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to parse response: %v", err)
			}

			if tt.wantErr {
				if resp["error"] == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if resp["error"] != nil {
					t.Errorf("unexpected error: %v", resp["error"])
				}
				if tt.checkResult != nil {
					tt.checkResult(t, resp)
				}
			}
		})
	}
}

func TestPanicRecovery(t *testing.T) {
	e := NewEndpoint()
	e.Register("panic", &panicMethods{})

	tests := []struct {
		name   string
		method string
	}{
		{"PanicMethod", "panic.PanicMethod"},
		{"PanicWithContext", "panic.PanicWithContext"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := `{"jsonrpc":"2.0","method":"` + tt.method + `","params":[],"id":1}`
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			serveRPC(e).ServeHTTP(rec, req)

			var resp map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to parse response: %v", err)
			}

			if resp["error"] == nil {
				t.Error("expected error for panic")
			}
			errObj := resp["error"].(map[string]interface{})
			if int(errObj["code"].(float64)) != CodeInternalError {
				t.Errorf("got error code %v, want %d", errObj["code"], CodeInternalError)
			}
		})
	}
}

func TestUnexportedMethodsNotRegistered(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &unexportedMethods{})

	body := `{"jsonrpc":"2.0","method":"test.hidden","params":[],"id":1}`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp["error"] == nil {
		t.Error("expected error for unexported method")
	}
	errObj := resp["error"].(map[string]interface{})
	if int(errObj["code"].(float64)) != CodeMethodNotFound {
		t.Errorf("got error code %v, want %d (method not found)", errObj["code"], CodeMethodNotFound)
	}
}

type unexportedMethods struct{}

func (m *unexportedMethods) hidden() string {
	return "should not be callable"
}

func (m *unexportedMethods) Visible() string {
	return "visible"
}

func TestBatchWithMixedResults(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &testMethods{})
	e.Register("math", &mathMethods{})

	body := `[
		{"jsonrpc":"2.0","method":"test.Echo","params":["hello"],"id":1},
		{"jsonrpc":"2.0","method":"test.Nonexistent","params":[],"id":2},
		{"jsonrpc":"2.0","method":"math.Add","params":[1,2],"id":3}
	]`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	var resp []map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if len(resp) != 3 {
		t.Fatalf("got %d responses, want 3", len(resp))
	}

	if resp[0]["result"] != "hello" {
		t.Errorf("first result should be 'hello'")
	}
	if resp[1]["error"] == nil {
		t.Errorf("second result should be an error")
	}
	if resp[2]["result"].(float64) != 3 {
		t.Errorf("third result should be 3")
	}
}

func TestBatchWithNotifications(t *testing.T) {
	e := NewEndpoint()
	notify := &notifyMethods{called: false}
	e.Register("notify", notify)
	e.Register("math", &mathMethods{})

	body := `[
		{"jsonrpc":"2.0","method":"notify.Ping","params":[]},
		{"jsonrpc":"2.0","method":"math.Add","params":[1,2],"id":1}
	]`
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	serveRPC(e).ServeHTTP(rec, req)

	if !notify.called {
		t.Error("notification should have been called")
	}

	var resp []map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)

	if len(resp) != 1 {
		t.Errorf("got %d responses, want 1 (notification should not produce response)", len(resp))
	}
}
