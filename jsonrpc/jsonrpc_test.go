package jsonrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mnehpets/oneserve/endpoint"
)

type MathMethods struct{}

func (m *MathMethods) Add(ctx context.Context, a, b int) (int, error) {
	return a + b, nil
}

func (m *MathMethods) Sub(ctx context.Context, args struct {
	A int `json:"a"`
	B int `json:"b"`
}) (int, error) {
	return args.A - args.B, nil
}

func (m *MathMethods) Fail(ctx context.Context) (string, error) {
	return "", &JSONRPCError{Code: -32000, Message: "Custom error"}
}

func TestEndpointIntegration(t *testing.T) {
	e := NewEndpoint()
	e.Register("math", &MathMethods{})

	handler := endpoint.Handler(e.Endpoint)

	req := httptest.NewRequest(http.MethodPost, "/rpc", bytes.NewBufferString(`{"jsonrpc":"2.0","method":"math.add","params":[1,2],"id":1}`))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	result := resp["result"].(float64)
	if result != 3 {
		t.Errorf("expected result 3, got %v", result)
	}
}

func TestPOSTOnly(t *testing.T) {
	e := NewEndpoint()
	handler := endpoint.Handler(e.Endpoint)

	req := httptest.NewRequest(http.MethodGet, "/rpc", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

func TestMethodRegistrationWithNamespace(t *testing.T) {
	e := NewEndpoint()
	e.Register("math", &MathMethods{})

	if len(e.methods) != 3 {
		t.Errorf("expected 3 methods, got %d", len(e.methods))
	}

	_, ok := e.methods["math.add"]
	if !ok {
		t.Error("expected math.add method to be registered")
	}
}

func TestMethodRegistrationWithoutNamespace(t *testing.T) {
	e := NewEndpoint()
	e.Register("", &MathMethods{})

	_, ok := e.methods["add"]
	if !ok {
		t.Error("expected add method to be registered")
	}
}

func TestSingleRequestSuccess(t *testing.T) {
	e := NewEndpoint()
	e.Register("math", &MathMethods{})

	body := []byte(`{"jsonrpc":"2.0","method":"math.add","params":[1,2],"id":1}`)
	r := &http.Request{
		Body:   io.NopCloser(bytes.NewReader(body)),
		Method: http.MethodPost,
	}
	r = r.WithContext(context.Background())

	renderer, err := e.handleBody(nil, r, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w := httptest.NewRecorder()
	if err := renderer.Render(w, r); err != nil {
		t.Fatalf("render error: %v", err)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if resp["jsonrpc"] != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %v", resp["jsonrpc"])
	}
}

func TestNotificationNoID(t *testing.T) {
	e := NewEndpoint()
	e.Register("math", &MathMethods{})

	body := []byte(`{"jsonrpc":"2.0","method":"math.add","params":[1,2]}`)
	r := &http.Request{
		Body:   io.NopCloser(bytes.NewReader(body)),
		Method: http.MethodPost,
	}
	r = r.WithContext(context.Background())

	renderer, err := e.handleBody(nil, r, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := renderer.(*endpoint.NoContentRenderer); !ok {
		t.Error("expected NoContentRenderer for notification")
	}
}

func TestBatchRequest(t *testing.T) {
	e := NewEndpoint()
	e.Register("math", &MathMethods{})

	body := []byte(`[
		{"jsonrpc":"2.0","method":"math.add","params":[1,2],"id":1},
		{"jsonrpc":"2.0","method":"math.add","params":[3,4],"id":2}
	]`)
	r := &http.Request{
		Body:   io.NopCloser(bytes.NewReader(body)),
		Method: http.MethodPost,
	}
	r = r.WithContext(context.Background())

	renderer, err := e.handleBody(nil, r, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w := httptest.NewRecorder()
	if err := renderer.Render(w, r); err != nil {
		t.Fatalf("render error: %v", err)
	}

	var resp []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(resp) != 2 {
		t.Errorf("expected 2 responses, got %d", len(resp))
	}

	result1 := resp[0]["result"].(float64)
	if result1 != 3 {
		t.Errorf("expected result 3, got %v", result1)
	}
}

func TestEmptyBatch(t *testing.T) {
	e := NewEndpoint()
	e.Register("math", &MathMethods{})

	body := []byte(`[]`)
	r := &http.Request{
		Body:   io.NopCloser(bytes.NewReader(body)),
		Method: http.MethodPost,
	}
	r = r.WithContext(context.Background())

	renderer, err := e.handleBody(nil, r, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w := httptest.NewRecorder()
	if err := renderer.Render(w, r); err != nil {
		t.Fatalf("render error: %v", err)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	errObj := resp["error"].(map[string]interface{})
	if errObj["code"].(float64) != float64(InvalidRequest) {
		t.Errorf("expected invalid request error, got %v", errObj)
	}
}

func TestParseError(t *testing.T) {
	e := NewEndpoint()

	body := []byte(`{invalid json`)
	r := &http.Request{
		Body:   io.NopCloser(bytes.NewReader(body)),
		Method: http.MethodPost,
	}
	r = r.WithContext(context.Background())

	renderer, err := e.handleBody(nil, r, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w := httptest.NewRecorder()
	if err := renderer.Render(w, r); err != nil {
		t.Fatalf("render error: %v", err)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	errObj := resp["error"].(map[string]interface{})
	if errObj["code"].(float64) != float64(ParseError) {
		t.Errorf("expected parse error, got %v", errObj)
	}
}

func TestInvalidRequest(t *testing.T) {
	e := NewEndpoint()

	body := []byte(`{"jsonrpc":"1.0","id":1}`)
	r := &http.Request{
		Body:   io.NopCloser(bytes.NewReader(body)),
		Method: http.MethodPost,
	}
	r = r.WithContext(context.Background())

	renderer, err := e.handleBody(nil, r, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w := httptest.NewRecorder()
	if err := renderer.Render(w, r); err != nil {
		t.Fatalf("render error: %v", err)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	errObj := resp["error"].(map[string]interface{})
	if errObj["code"].(float64) != float64(InvalidRequest) {
		t.Errorf("expected invalid request error, got %v", errObj)
	}
}

func TestMethodNotFound(t *testing.T) {
	e := NewEndpoint()
	e.Register("math", &MathMethods{})

	body := []byte(`{"jsonrpc":"2.0","method":"math.multiply","params":[1,2],"id":1}`)
	r := &http.Request{
		Body:   io.NopCloser(bytes.NewReader(body)),
		Method: http.MethodPost,
	}
	r = r.WithContext(context.Background())

	renderer, err := e.handleBody(nil, r, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w := httptest.NewRecorder()
	if err := renderer.Render(w, r); err != nil {
		t.Fatalf("render error: %v", err)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	errObj := resp["error"].(map[string]interface{})
	if errObj["code"].(float64) != float64(MethodNotFound) {
		t.Errorf("expected method not found error, got %v", errObj)
	}
}

func TestInvalidParams(t *testing.T) {
	e := NewEndpoint()
	e.Register("math", &MathMethods{})

	body := []byte(`{"jsonrpc":"2.0","method":"math.add","params":"not an array","id":1}`)
	r := &http.Request{
		Body:   io.NopCloser(bytes.NewReader(body)),
		Method: http.MethodPost,
	}
	r = r.WithContext(context.Background())

	renderer, err := e.handleBody(nil, r, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w := httptest.NewRecorder()
	if err := renderer.Render(w, r); err != nil {
		t.Fatalf("render error: %v", err)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	errObj := resp["error"].(map[string]interface{})
	if errObj["code"].(float64) != float64(InvalidParams) {
		t.Errorf("expected invalid params error, got %v", errObj)
	}
}

func TestCustomError(t *testing.T) {
	e := NewEndpoint()
	e.Register("math", &MathMethods{})

	body := []byte(`{"jsonrpc":"2.0","method":"math.fail","id":1}`)
	r := &http.Request{
		Body:   io.NopCloser(bytes.NewReader(body)),
		Method: http.MethodPost,
	}
	r = r.WithContext(context.Background())

	renderer, err := e.handleBody(nil, r, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w := httptest.NewRecorder()
	if err := renderer.Render(w, r); err != nil {
		t.Fatalf("render error: %v", err)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	errObj := resp["error"].(map[string]interface{})
	if errObj["code"].(float64) != -32000 {
		t.Errorf("expected custom error code -32000, got %v", errObj)
	}
	if errObj["message"] != "Custom error" {
		t.Errorf("expected custom error message, got %v", errObj)
	}
}

func TestContextPropagation(t *testing.T) {
	type ContextKey string
	const TestKey ContextKey = "test"

	e := NewEndpoint()
	e.Register("math", &MathMethods{})

	body := []byte(`{"jsonrpc":"2.0","method":"math.add","params":[1,2],"id":1}`)
	r := &http.Request{
		Body:   io.NopCloser(bytes.NewReader(body)),
		Method: http.MethodPost,
	}
	ctx := context.WithValue(context.Background(), TestKey, "test-value")
	r = r.WithContext(ctx)

	renderer, err := e.handleBody(nil, r, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w := httptest.NewRecorder()
	if err := renderer.Render(w, r); err != nil {
		t.Fatalf("render error: %v", err)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	result := resp["result"].(float64)
	if result != 3 {
		t.Errorf("expected result 3, got %v", result)
	}
}

func TestContentTypeValidation(t *testing.T) {
	e := NewEndpoint()
	e.Register("math", &MathMethods{})
	handler := endpoint.Handler(e.Endpoint)

	req := httptest.NewRequest(http.MethodPost, "/rpc", bytes.NewBufferString(`{"jsonrpc":"2.0","method":"math.add","params":[1,2],"id":1}`))
	req.Header.Set("Content-Type", "text/plain")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("expected status 415, got %d", w.Code)
	}
}

func TestMissingContentType(t *testing.T) {
	e := NewEndpoint()
	e.Register("math", &MathMethods{})
	handler := endpoint.Handler(e.Endpoint)

	req := httptest.NewRequest(http.MethodPost, "/rpc", bytes.NewBufferString(`{"jsonrpc":"2.0","method":"math.add","params":[1,2],"id":1}`))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

func TestBatchWithNotification(t *testing.T) {
	e := NewEndpoint()
	e.Register("math", &MathMethods{})

	body := []byte(`[
		{"jsonrpc":"2.0","method":"math.add","params":[1,2],"id":1},
		{"jsonrpc":"2.0","method":"math.add","params":[3,4]},
		{"jsonrpc":"2.0","method":"math.add","params":[5,6],"id":3}
	]`)
	r := &http.Request{
		Body:   io.NopCloser(bytes.NewReader(body)),
		Method: http.MethodPost,
	}
	r = r.WithContext(context.Background())

	renderer, err := e.handleBody(nil, r, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	w := httptest.NewRecorder()
	if err := renderer.Render(w, r); err != nil {
		t.Fatalf("render error: %v", err)
	}

	var resp []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(resp) != 2 {
		t.Errorf("expected 2 responses (notification excluded), got %d", len(resp))
	}
}

func TestNamedParams(t *testing.T) {
	e := NewEndpoint()
	e.Register("math", &MathMethods{})
	handler := endpoint.Handler(e.Endpoint)

	req := httptest.NewRequest(http.MethodPost, "/rpc", bytes.NewBufferString(`{"jsonrpc":"2.0","method":"math.sub","params":{"a":5,"b":3},"id":1}`))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	result := resp["result"].(float64)
	if result != 2 {
		t.Errorf("expected result 2, got %v", result)
	}
}

func TestPositionalParamsWithStruct(t *testing.T) {
	e := NewEndpoint()
	e.Register("math", &MathMethods{})
	handler := endpoint.Handler(e.Endpoint)

	req := httptest.NewRequest(http.MethodPost, "/rpc", bytes.NewBufferString(`{"jsonrpc":"2.0","method":"math.sub","params":[5,3],"id":1}`))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	result := resp["result"].(float64)
	if result != 2 {
		t.Errorf("expected result 2, got %v", result)
	}
}
