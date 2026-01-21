package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewSecurityHeadersProcessor(t *testing.T) {
	p := NewSecurityHeadersProcessor()
	if p.HSTS == nil {
		t.Fatal("HSTS should be configured by default")
	}
	if p.HSTS.MaxAge != 31536000 {
		t.Errorf("HSTS MaxAge: got %d, want %d", p.HSTS.MaxAge, 31536000)
	}
	if !p.HSTS.IncludeSubDomains {
		t.Error("HSTS IncludeSubDomains should be true by default")
	}
	if p.HSTS.Preload {
		t.Error("HSTS Preload should be false by default")
	}
	if p.ReferrerPolicy != "strict-origin-when-cross-origin" {
		t.Errorf("ReferrerPolicy: got %q, want %q", p.ReferrerPolicy, "strict-origin-when-cross-origin")
	}
	if p.FrameOptions != "DENY" {
		t.Errorf("FrameOptions: got %q, want %q", p.FrameOptions, "DENY")
	}
	if !p.ContentTypeOptions {
		t.Error("ContentTypeOptions should be true by default")
	}
	if p.CORS != nil {
		t.Error("CORS should be nil by default")
	}
}

func TestSecurityHeadersProcessor_DefaultHeaders(t *testing.T) {
	p := NewSecurityHeadersProcessor()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	nextCalled := false
	next := func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		return nil
	}

	err := p.Process(w, r, next)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}
	if !nextCalled {
		t.Fatal("next was not called")
	}

	// Check HSTS header
	hsts := w.Header().Get("Strict-Transport-Security")
	if !strings.Contains(hsts, "max-age=31536000") {
		t.Errorf("HSTS header: got %q, want to contain 'max-age=31536000'", hsts)
	}
	if !strings.Contains(hsts, "includeSubDomains") {
		t.Errorf("HSTS header: got %q, want to contain 'includeSubDomains'", hsts)
	}
	if strings.Contains(hsts, "preload") {
		t.Errorf("HSTS header: got %q, should not contain 'preload'", hsts)
	}

	// Check Referrer-Policy header
	refPolicy := w.Header().Get("Referrer-Policy")
	if refPolicy != "strict-origin-when-cross-origin" {
		t.Errorf("Referrer-Policy: got %q, want %q", refPolicy, "strict-origin-when-cross-origin")
	}

	// Check X-Frame-Options header
	frameOpts := w.Header().Get("X-Frame-Options")
	if frameOpts != "DENY" {
		t.Errorf("X-Frame-Options: got %q, want %q", frameOpts, "DENY")
	}

	// Check X-Content-Type-Options header
	contentTypeOpts := w.Header().Get("X-Content-Type-Options")
	if contentTypeOpts != "nosniff" {
		t.Errorf("X-Content-Type-Options: got %q, want %q", contentTypeOpts, "nosniff")
	}

	// Check that CORS headers are not set
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("Access-Control-Allow-Origin should not be set by default")
	}
}

func TestSecurityHeadersProcessor_CustomHSTS(t *testing.T) {
	p := NewSecurityHeadersProcessor().WithHSTS(7776000, false, true)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	next := func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}

	err := p.Process(w, r, next)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	hsts := w.Header().Get("Strict-Transport-Security")
	if !strings.Contains(hsts, "max-age=7776000") {
		t.Errorf("HSTS header: got %q, want to contain 'max-age=7776000'", hsts)
	}
	if strings.Contains(hsts, "includeSubDomains") {
		t.Errorf("HSTS header: got %q, should not contain 'includeSubDomains'", hsts)
	}
	if !strings.Contains(hsts, "preload") {
		t.Errorf("HSTS header: got %q, want to contain 'preload'", hsts)
	}
}

func TestSecurityHeadersProcessor_DisableHSTS(t *testing.T) {
	p := NewSecurityHeadersProcessor().WithoutHSTS()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	next := func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}

	err := p.Process(w, r, next)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	if w.Header().Get("Strict-Transport-Security") != "" {
		t.Error("Strict-Transport-Security should not be set when HSTS is disabled")
	}
}

func TestSecurityHeadersProcessor_CustomReferrerPolicy(t *testing.T) {
	p := NewSecurityHeadersProcessor().WithReferrerPolicy("no-referrer")
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	next := func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}

	err := p.Process(w, r, next)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	refPolicy := w.Header().Get("Referrer-Policy")
	if refPolicy != "no-referrer" {
		t.Errorf("Referrer-Policy: got %q, want %q", refPolicy, "no-referrer")
	}
}

func TestSecurityHeadersProcessor_CustomFrameOptions(t *testing.T) {
	p := NewSecurityHeadersProcessor().WithFrameOptions("SAMEORIGIN")
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	next := func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}

	err := p.Process(w, r, next)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	frameOpts := w.Header().Get("X-Frame-Options")
	if frameOpts != "SAMEORIGIN" {
		t.Errorf("X-Frame-Options: got %q, want %q", frameOpts, "SAMEORIGIN")
	}
}

func TestSecurityHeadersProcessor_DisableContentTypeOptions(t *testing.T) {
	p := NewSecurityHeadersProcessor().WithContentTypeOptions(false)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)

	next := func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}

	err := p.Process(w, r, next)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	if w.Header().Get("X-Content-Type-Options") != "" {
		t.Error("X-Content-Type-Options should not be set when disabled")
	}
}

func TestSecurityHeadersProcessor_CORS_SimpleOrigin(t *testing.T) {
	p := NewSecurityHeadersProcessor().WithCORS(&CORSConfig{
		AllowedOrigins: []string{"https://example.com"},
		AllowedMethods: []string{"GET", "POST"},
		AllowedHeaders: []string{"Content-Type"},
		MaxAge:         3600,
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Origin", "https://example.com")

	next := func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}

	err := p.Process(w, r, next)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	origin := w.Header().Get("Access-Control-Allow-Origin")
	if origin != "https://example.com" {
		t.Errorf("Access-Control-Allow-Origin: got %q, want %q", origin, "https://example.com")
	}

	// For simple (non-preflight) requests, methods and headers should NOT be set
	methods := w.Header().Get("Access-Control-Allow-Methods")
	if methods != "" {
		t.Errorf("Access-Control-Allow-Methods should not be set for simple requests, got %q", methods)
	}

	headers := w.Header().Get("Access-Control-Allow-Headers")
	if headers != "" {
		t.Errorf("Access-Control-Allow-Headers should not be set for simple requests, got %q", headers)
	}
}

func TestSecurityHeadersProcessor_CORS_Wildcard(t *testing.T) {
	p := NewSecurityHeadersProcessor().WithCORS(&CORSConfig{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET"},
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Origin", "https://anysite.com")

	next := func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}

	err := p.Process(w, r, next)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	origin := w.Header().Get("Access-Control-Allow-Origin")
	if origin != "*" {
		t.Errorf("Access-Control-Allow-Origin: got %q, want %q", origin, "*")
	}
}

func TestSecurityHeadersProcessor_CORS_WildcardWithCredentials(t *testing.T) {
	// Security test: Wildcard with credentials should not set wildcard origin
	p := NewSecurityHeadersProcessor().WithCORS(&CORSConfig{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET"},
		AllowCredentials: true,
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Origin", "https://anysite.com")

	next := func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}

	err := p.Process(w, r, next)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	origin := w.Header().Get("Access-Control-Allow-Origin")
	if origin != "" {
		t.Errorf("Access-Control-Allow-Origin should not be set when using wildcard with credentials, got %q", origin)
	}
}

func TestSecurityHeadersProcessor_CORS_UnauthorizedOrigin(t *testing.T) {
	p := NewSecurityHeadersProcessor().WithCORS(&CORSConfig{
		AllowedOrigins: []string{"https://example.com"},
		AllowedMethods: []string{"GET"},
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Origin", "https://evil.com")

	next := func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}

	err := p.Process(w, r, next)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	origin := w.Header().Get("Access-Control-Allow-Origin")
	if origin != "" {
		t.Errorf("Access-Control-Allow-Origin should not be set for unauthorized origin, got %q", origin)
	}
}

func TestSecurityHeadersProcessor_CORS_NoOriginHeader(t *testing.T) {
	p := NewSecurityHeadersProcessor().WithCORS(&CORSConfig{
		AllowedOrigins: []string{"https://example.com"},
		AllowedMethods: []string{"GET"},
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	// No Origin header set

	next := func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}

	err := p.Process(w, r, next)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	// CORS headers should NOT be set when there's no Origin header
	origin := w.Header().Get("Access-Control-Allow-Origin")
	if origin != "" {
		t.Errorf("Access-Control-Allow-Origin should not be set without Origin header, got %q", origin)
	}
}

func TestSecurityHeadersProcessor_CORS_Credentials(t *testing.T) {
	p := NewSecurityHeadersProcessor().WithCORS(&CORSConfig{
		AllowedOrigins:   []string{"https://example.com"},
		AllowedMethods:   []string{"GET"},
		AllowCredentials: true,
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Origin", "https://example.com")

	next := func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}

	err := p.Process(w, r, next)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	credentials := w.Header().Get("Access-Control-Allow-Credentials")
	if credentials != "true" {
		t.Errorf("Access-Control-Allow-Credentials: got %q, want %q", credentials, "true")
	}
}

func TestSecurityHeadersProcessor_CORS_PreflightMaxAge(t *testing.T) {
	p := NewSecurityHeadersProcessor().WithCORS(&CORSConfig{
		AllowedOrigins: []string{"https://example.com"},
		AllowedMethods: []string{"GET", "POST"},
		AllowedHeaders: []string{"Content-Type", "Authorization"},
		MaxAge:         7200,
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("OPTIONS", "/", nil)
	r.Header.Set("Origin", "https://example.com")

	next := func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}

	err := p.Process(w, r, next)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	// For preflight requests, all CORS headers should be set
	origin := w.Header().Get("Access-Control-Allow-Origin")
	if origin != "https://example.com" {
		t.Errorf("Access-Control-Allow-Origin: got %q, want %q", origin, "https://example.com")
	}

	methods := w.Header().Get("Access-Control-Allow-Methods")
	if methods != "GET, POST" {
		t.Errorf("Access-Control-Allow-Methods: got %q, want %q", methods, "GET, POST")
	}

	headers := w.Header().Get("Access-Control-Allow-Headers")
	if headers != "Content-Type, Authorization" {
		t.Errorf("Access-Control-Allow-Headers: got %q, want %q", headers, "Content-Type, Authorization")
	}

	maxAge := w.Header().Get("Access-Control-Max-Age")
	if maxAge != "7200" {
		t.Errorf("Access-Control-Max-Age: got %q, want %q", maxAge, "7200")
	}
}

func TestSecurityHeadersProcessor_CORS_ExposedHeaders(t *testing.T) {
	p := NewSecurityHeadersProcessor().WithCORS(&CORSConfig{
		AllowedOrigins: []string{"https://example.com"},
		ExposedHeaders: []string{"X-Custom-Header", "X-Another-Header"},
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Origin", "https://example.com")

	next := func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}

	err := p.Process(w, r, next)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	exposed := w.Header().Get("Access-Control-Expose-Headers")
	if exposed != "X-Custom-Header, X-Another-Header" {
		t.Errorf("Access-Control-Expose-Headers: got %q, want %q", exposed, "X-Custom-Header, X-Another-Header")
	}
}

func TestSecurityHeadersProcessor_AllHeadersCombined(t *testing.T) {
	p := NewSecurityHeadersProcessor().
		WithHSTS(7776000, true, false).
		WithReferrerPolicy("same-origin").
		WithFrameOptions("SAMEORIGIN").
		WithContentTypeOptions(true).
		WithCORS(&CORSConfig{
			AllowedOrigins: []string{"https://example.com"},
			AllowedMethods: []string{"GET", "POST", "PUT"},
			AllowedHeaders: []string{"Content-Type", "Authorization"},
			AllowCredentials: true,
			MaxAge:         3600,
		})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Origin", "https://example.com")

	next := func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}

	err := p.Process(w, r, next)
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	// Verify all headers are set correctly
	if !strings.Contains(w.Header().Get("Strict-Transport-Security"), "max-age=7776000") {
		t.Error("HSTS header not set correctly")
	}
	if w.Header().Get("Referrer-Policy") != "same-origin" {
		t.Error("Referrer-Policy not set correctly")
	}
	if w.Header().Get("X-Frame-Options") != "SAMEORIGIN" {
		t.Error("X-Frame-Options not set correctly")
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("X-Content-Type-Options not set correctly")
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Error("Access-Control-Allow-Origin not set correctly")
	}
	if w.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Error("Access-Control-Allow-Credentials not set correctly")
	}
}

func TestFormatHSTS(t *testing.T) {
	tests := []struct {
		name   string
		config *HSTSConfig
		want   string
	}{
		{
			name:   "nil config",
			config: nil,
			want:   "",
		},
		{
			name:   "zero max age",
			config: &HSTSConfig{MaxAge: 0},
			want:   "",
		},
		{
			name:   "basic config",
			config: &HSTSConfig{MaxAge: 3600},
			want:   "max-age=3600",
		},
		{
			name:   "with subdomains",
			config: &HSTSConfig{MaxAge: 3600, IncludeSubDomains: true},
			want:   "max-age=3600; includeSubDomains",
		},
		{
			name:   "with preload",
			config: &HSTSConfig{MaxAge: 3600, Preload: true},
			want:   "max-age=3600; preload",
		},
		{
			name:   "all options",
			config: &HSTSConfig{MaxAge: 31536000, IncludeSubDomains: true, Preload: true},
			want:   "max-age=31536000; includeSubDomains; preload",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatHSTS(tt.config)
			if got != tt.want {
				t.Errorf("formatHSTS() = %q, want %q", got, tt.want)
			}
		})
	}
}
