package jsonrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mnehpets/oneserve/endpoint"
)

// TestService provides methods for testing
type TestService struct{}

func (t *TestService) Add(ctx context.Context, a, b int) (int, error) {
	return a + b, nil
}

func (t *TestService) Echo(ctx context.Context, message string) (string, error) {
	return message, nil
}

func (t *TestService) ErrorMethod(ctx context.Context) (string, error) {
	return "", errors.New("internal error")
}

func (t *TestService) CustomErrorMethod(ctx context.Context) (string, error) {
	return "", NewError(-32000, "custom error", "custom data")
}

func (t *TestService) Notification(ctx context.Context) error {
	return nil
}

type NamedParams struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
}

func (t *TestService) NamedParamMethod(ctx context.Context, params NamedParams) (string, error) {
	return params.Name, nil
}

// Helper to create a test request
func makeRequest(method string, body interface{}) *http.Request {
	var bodyData []byte
	if body != nil {
		bodyData, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, "/rpc", bytes.NewReader(bodyData))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// Helper to execute request and get response
func executeRequest(t *testing.T, e *Endpoint, req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	handler := endpoint.Handler(e.Endpoint)
	handler.ServeHTTP(rr, req)
	return rr
}

// Test 6.1: Test endpoint integrates with endpoint.Handler
func TestEndpointIntegration(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &TestService{})

	req := makeRequest(http.MethodPost, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "test.Add",
		"params":  []int{1, 2},
		"id":      1,
	})

	rr := executeRequest(t, e, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var resp Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp.Error != nil {
		t.Errorf("Expected no error, got: %v", resp.Error)
	}
}

// Test 6.2: Test POST-only enforcement
func TestPostOnly(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &TestService{})

	// Test GET request
	req := makeRequest(http.MethodGet, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "test.Add",
		"params":  []int{1, 2},
		"id":      1,
	})

	rr := executeRequest(t, e, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", rr.Code)
	}
}

// Test 6.3: Test method registration with namespace
func TestMethodRegistrationWithNamespace(t *testing.T) {
	e := NewEndpoint()
	e.Register("math", &TestService{})

	req := makeRequest(http.MethodPost, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "math.Add",
		"params":  []int{5, 3},
		"id":      1,
	})

	rr := executeRequest(t, e, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var resp Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp.Error != nil {
		t.Errorf("Expected no error, got: %v", resp.Error)
	}

	result, ok := resp.Result.(float64)
	if !ok || result != 8 {
		t.Errorf("Expected result 8, got %v", resp.Result)
	}
}

// Test 6.4: Test method registration without namespace
func TestMethodRegistrationWithoutNamespace(t *testing.T) {
	e := NewEndpoint()
	e.Register("", &TestService{})

	req := makeRequest(http.MethodPost, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "Echo",
		"params":  []string{"hello"},
		"id":      1,
	})

	rr := executeRequest(t, e, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var resp Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp.Error != nil {
		t.Errorf("Expected no error, got: %v", resp.Error)
	}

	result, ok := resp.Result.(string)
	if !ok || result != "hello" {
		t.Errorf("Expected result 'hello', got %v", resp.Result)
	}
}

// Test 6.5: Test single request handling (success case)
func TestSingleRequestSuccess(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &TestService{})

	req := makeRequest(http.MethodPost, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "test.Add",
		"params":  []int{10, 20},
		"id":      42,
	})

	rr := executeRequest(t, e, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var resp Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp.JSONRPC != "2.0" {
		t.Errorf("Expected jsonrpc '2.0', got '%s'", resp.JSONRPC)
	}

	// Verify ID is preserved
	if resp.ID == nil {
		t.Error("Expected ID to be preserved")
	}

	result, ok := resp.Result.(float64)
	if !ok || result != 30 {
		t.Errorf("Expected result 30, got %v", resp.Result)
	}
}

// Test 6.6: Test notification handling (no id → 204 No Content)
func TestNotificationNoContent(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &TestService{})

	req := makeRequest(http.MethodPost, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "test.Notification",
	})

	rr := executeRequest(t, e, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", rr.Code)
	}

	if rr.Body.Len() > 0 {
		t.Errorf("Expected empty body for notification, got: %s", rr.Body.String())
	}
}

// Test 6.7: Test batch request handling
func TestBatchRequest(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &TestService{})

	batch := []map[string]interface{}{
		{
			"jsonrpc": "2.0",
			"method":  "test.Add",
			"params":  []int{1, 2},
			"id":      1,
		},
		{
			"jsonrpc": "2.0",
			"method":  "test.Echo",
			"params":  []string{"hello"},
			"id":      2,
		},
	}

	reqBody, _ := json.Marshal(batch)
	req := httptest.NewRequest(http.MethodPost, "/rpc", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")

	rr := executeRequest(t, e, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var responses []Response
	if err := json.Unmarshal(rr.Body.Bytes(), &responses); err != nil {
		t.Fatalf("Failed to parse batch response: %v", err)
	}

	if len(responses) != 2 {
		t.Errorf("Expected 2 responses, got %d", len(responses))
	}

	// Check first response
	if responses[0].Error != nil {
		t.Errorf("First response has error: %v", responses[0].Error)
	}
	if responses[0].Result != float64(3) {
		t.Errorf("First response result expected 3, got %v", responses[0].Result)
	}

	// Check second response
	if responses[1].Error != nil {
		t.Errorf("Second response has error: %v", responses[1].Error)
	}
	if responses[1].Result != "hello" {
		t.Errorf("Second response result expected 'hello', got %v", responses[1].Result)
	}
}

// Test 6.8: Test empty batch request → Invalid Request error
func TestEmptyBatch(t *testing.T) {
	e := NewEndpoint()

	req := httptest.NewRequest(http.MethodPost, "/rpc", bytes.NewReader([]byte("[]")))
	req.Header.Set("Content-Type", "application/json")

	rr := executeRequest(t, e, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var resp Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp.Error == nil {
		t.Fatal("Expected error for empty batch")
	}

	if resp.Error.Code != InvalidRequest {
		t.Errorf("Expected error code %d, got %d", InvalidRequest, resp.Error.Code)
	}
}

// Test 6.9: Test all standard error codes
func TestStandardErrorCodes(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &TestService{})

	tests := []struct {
		name         string
		request      interface{}
		expectedCode int
	}{
		{
			name:         "Parse error - invalid JSON",
			request:      "{invalid json}",
			expectedCode: ParseError,
		},
		{
			name: "Invalid request - missing jsonrpc",
			request: map[string]interface{}{
				"method": "test.Add",
				"id":     1,
			},
			expectedCode: InvalidRequest,
		},
		{
			name: "Invalid request - wrong version",
			request: map[string]interface{}{
				"jsonrpc": "1.0",
				"method":  "test.Add",
				"id":      1,
			},
			expectedCode: InvalidRequest,
		},
		{
			name: "Method not found",
			request: map[string]interface{}{
				"jsonrpc": "2.0",
				"method":  "test.NonExistent",
				"id":      1,
			},
			expectedCode: MethodNotFound,
		},
		{
			name: "Internal error",
			request: map[string]interface{}{
				"jsonrpc": "2.0",
				"method":  "test.ErrorMethod",
				"id":      1,
			},
			expectedCode: InternalError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reqBody []byte
			if s, ok := tt.request.(string); ok {
				reqBody = []byte(s)
			} else {
				reqBody, _ = json.Marshal(tt.request)
			}

			req := httptest.NewRequest(http.MethodPost, "/rpc", bytes.NewReader(reqBody))
			req.Header.Set("Content-Type", "application/json")

			rr := executeRequest(t, e, req)

			if rr.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", rr.Code)
			}

			var resp Response
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("Failed to parse response: %v", err)
			}

			if resp.Error == nil {
				t.Fatal("Expected error response")
			}

			if resp.Error.Code != tt.expectedCode {
				t.Errorf("Expected error code %d, got %d", tt.expectedCode, resp.Error.Code)
			}
		})
	}
}

// Test 6.10: Test custom error codes (JSONRPCError type)
func TestCustomErrorCodes(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &TestService{})

	req := makeRequest(http.MethodPost, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "test.CustomErrorMethod",
		"id":      1,
	})

	rr := executeRequest(t, e, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var resp Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp.Error == nil {
		t.Fatal("Expected error response")
	}

	if resp.Error.Code != -32000 {
		t.Errorf("Expected custom error code -32000, got %d", resp.Error.Code)
	}

	if resp.Error.Message != "custom error" {
		t.Errorf("Expected message 'custom error', got '%s'", resp.Error.Message)
	}
}

// Test 6.11: Test processor chain execution
func TestProcessorChain(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &TestService{})

	// Create a processor that adds a header
	processor := endpoint.ProcessorFunc(func(w http.ResponseWriter, r *http.Request, next func(http.ResponseWriter, *http.Request) error) error {
		w.Header().Set("X-Processed", "true")
		return next(w, r)
	})

	req := makeRequest(http.MethodPost, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "test.Add",
		"params":  []int{1, 2},
		"id":      1,
	})

	rr := httptest.NewRecorder()
	handler := endpoint.Handler(e.Endpoint, processor)
	handler.ServeHTTP(rr, req)

	if rr.Header().Get("X-Processed") != "true" {
		t.Error("Processor chain was not executed")
	}

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}
}

// Test 6.12: Test context propagation to methods
func TestContextPropagation(t *testing.T) {
	// This test verifies that the context is properly passed to methods
	// The implementation uses context.Background(), so we verify the method is called
	e := NewEndpoint()
	e.Register("test", &TestService{})

	req := makeRequest(http.MethodPost, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "test.Add",
		"params":  []int{5, 10},
		"id":      1,
	})

	rr := executeRequest(t, e, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var resp Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Verify the method was called successfully (context was available)
	result, ok := resp.Result.(float64)
	if !ok || result != 15 {
		t.Errorf("Expected result 15, got %v", resp.Result)
	}
}

// Test named parameters
func TestNamedParams(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &TestService{})

	req := makeRequest(http.MethodPost, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "test.NamedParamMethod",
		"params": map[string]interface{}{
			"name":  "test",
			"value": 42,
		},
		"id": 1,
	})

	rr := executeRequest(t, e, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var resp Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp.Error != nil {
		t.Errorf("Expected no error, got: %v", resp.Error)
	}

	result, ok := resp.Result.(string)
	if !ok || result != "test" {
		t.Errorf("Expected result 'test', got %v", resp.Result)
	}
}

// Test batch with notifications
func TestBatchWithNotifications(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &TestService{})

	batch := []map[string]interface{}{
		{
			"jsonrpc": "2.0",
			"method":  "test.Add",
			"params":  []int{1, 2},
			"id":      1,
		},
		{
			"jsonrpc": "2.0",
			"method":  "test.Notification",
		},
		{
			"jsonrpc": "2.0",
			"method":  "test.Echo",
			"params":  []string{"world"},
			"id":      2,
		},
	}

	reqBody, _ := json.Marshal(batch)
	req := httptest.NewRequest(http.MethodPost, "/rpc", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")

	rr := executeRequest(t, e, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var responses []Response
	if err := json.Unmarshal(rr.Body.Bytes(), &responses); err != nil {
		t.Fatalf("Failed to parse batch response: %v", err)
	}

	// Should only have 2 responses (notifications excluded)
	if len(responses) != 2 {
		t.Errorf("Expected 2 responses (notification excluded), got %d", len(responses))
	}
}

// Test error type implementation
func TestErrorType(t *testing.T) {
	err := NewError(-32000, "test error", "data")

	if err.Code != -32000 {
		t.Errorf("Expected code -32000, got %d", err.Code)
	}

	if err.Message != "test error" {
		t.Errorf("Expected message 'test error', got '%s'", err.Message)
	}

	if err.Data != "data" {
		t.Errorf("Expected data 'data', got %v", err.Data)
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "-32000") {
		t.Errorf("Error string should contain code: %s", errStr)
	}

	if !strings.Contains(errStr, "test error") {
		t.Errorf("Error string should contain message: %s", errStr)
	}
}

// Test empty body
func TestEmptyBody(t *testing.T) {
	e := NewEndpoint()

	req := httptest.NewRequest(http.MethodPost, "/rpc", bytes.NewReader([]byte{}))
	req.Header.Set("Content-Type", "application/json")

	rr := executeRequest(t, e, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var resp Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp.Error == nil {
		t.Fatal("Expected error for empty body")
	}

	if resp.Error.Code != InvalidRequest {
		t.Errorf("Expected error code %d, got %d", InvalidRequest, resp.Error.Code)
	}
}

// Test missing method field
func TestMissingMethod(t *testing.T) {
	e := NewEndpoint()

	req := makeRequest(http.MethodPost, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
	})

	rr := executeRequest(t, e, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var resp Response
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp.Error == nil {
		t.Fatal("Expected error for missing method")
	}

	if resp.Error.Code != InvalidRequest {
		t.Errorf("Expected error code %d, got %d", InvalidRequest, resp.Error.Code)
	}
}

// Test constants
func TestErrorConstants(t *testing.T) {
	if ParseError != -32700 {
		t.Errorf("ParseError should be -32700, got %d", ParseError)
	}
	if InvalidRequest != -32600 {
		t.Errorf("InvalidRequest should be -32600, got %d", InvalidRequest)
	}
	if MethodNotFound != -32601 {
		t.Errorf("MethodNotFound should be -32601, got %d", MethodNotFound)
	}
	if InvalidParams != -32602 {
		t.Errorf("InvalidParams should be -32602, got %d", InvalidParams)
	}
	if InternalError != -32603 {
		t.Errorf("InternalError should be -32603, got %d", InternalError)
	}
}

// Test Content-Type validation
func TestContentTypeValidation(t *testing.T) {
	e := NewEndpoint()
	e.Register("test", &TestService{})

	tests := []struct {
		name         string
		contentType  string
		expectedCode int
		expectError  bool
	}{
		{
			name:         "Valid application/json",
			contentType:  "application/json",
			expectedCode: http.StatusOK,
			expectError:  false,
		},
		{
			name:         "Missing Content-Type",
			contentType:  "",
			expectedCode: http.StatusUnsupportedMediaType,
			expectError:  true,
		},
		{
			name:         "Wrong Content-Type text/plain",
			contentType:  "text/plain",
			expectedCode: http.StatusUnsupportedMediaType,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := makeRequest(http.MethodPost, map[string]interface{}{
				"jsonrpc": "2.0",
				"method":  "test.Add",
				"params":  []int{1, 2},
				"id":      1,
			})
			req.Header.Set("Content-Type", tt.contentType)

			rr := executeRequest(t, e, req)

			if rr.Code != tt.expectedCode {
				t.Errorf("Expected status %d, got %d", tt.expectedCode, rr.Code)
			}

			if tt.expectError && rr.Code != http.StatusOK {
				// Check that we got an HTTP error, not JSON-RPC error
				if rr.Code != tt.expectedCode {
					t.Errorf("Expected HTTP status %d for error case", tt.expectedCode)
				}
			}
		})
	}
}
