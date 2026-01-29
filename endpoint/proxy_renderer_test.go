package endpoint

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestNewProxyRenderer_Success(t *testing.T) {
	p, err := NewProxyRenderer("http://example.com")
	if err != nil {
		t.Fatalf("NewProxyRenderer returned error: %v", err)
	}
	if p.Proxy == nil {
		t.Fatal("expected non-nil Proxy")
	}
}

func TestNewProxyRenderer_Errors(t *testing.T) {
	tests := []struct {
		name      string
		targetURL string
	}{
		{"Empty URL", ""},
		{"Relative URL", "/foo"},
		{"Malformed URL", "::invalid::"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewProxyRenderer(tt.targetURL)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestProxyRenderer_Render_ErrorsWhenNilProxy(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	p := &ProxyRenderer{Proxy: nil}
	err := p.Render(rec, req)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if rec.Flushed {
		t.Error("expected no response to be written")
	}
}

func TestProxyRenderer_Integration_ForwardsRequestAndResponse(t *testing.T) {
	// Upstream server that echos the request body
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected Method POST, got %s", r.Method)
		}
		if r.URL.Path != "/foo" {
			t.Errorf("expected Path /foo, got %s", r.URL.Path)
		}
		if r.URL.Query().Get("q") != "bar" {
			t.Errorf("expected Query q=bar, got %s", r.URL.Query().Get("q"))
		}

		body, _ := io.ReadAll(r.Body)
		if string(body) != "request body" {
			t.Errorf("expected Body 'request body', got %q", string(body))
		}

		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("response body"))
	}))
	defer upstream.Close()

	p, err := NewProxyRenderer(upstream.URL)
	if err != nil {
		t.Fatalf("failed to create renderer: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/foo?q=bar", strings.NewReader("request body"))

	if err := p.Render(rec, req); err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	resp := rec.Result()
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("expected status 201, got %d", resp.StatusCode)
	}

	respBody, _ := io.ReadAll(resp.Body)
	if string(respBody) != "response body" {
		t.Errorf("expected response body 'response body', got %q", string(respBody))
	}
}

func TestProxyRenderer_Integration_DropsHopByHopHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Connection") != "" {
			t.Error("expected Connection header to be removed")
		}
		if r.Header.Get("X-Custom-Hop") != "" {
			t.Error("expected X-Custom-Hop header to be removed (if listed in Connection)")
		}
		if r.Header.Get("X-Keep") != "true" {
			t.Error("expected X-Keep header to be preserved")
		}

		// Send back some headers
		w.Header().Set("Connection", "Upgrade, X-Response-Hop")
		w.Header().Set("Upgrade", "foo")
		w.Header().Set("X-Response-Hop", "drop-me")
		w.Header().Set("X-Response-Keep", "true")
	}))
	defer upstream.Close()

	p, err := NewProxyRenderer(upstream.URL)
	if err != nil {
		t.Fatalf("failed to create renderer: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Connection", "X-Custom-Hop")
	req.Header.Set("X-Custom-Hop", "drop-me")
	req.Header.Set("X-Keep", "true")

	if err := p.Render(rec, req); err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	resp := rec.Result()
	if resp.Header.Get("Connection") != "" {
		t.Error("expected Connection header to be removed from response")
	}
	if resp.Header.Get("X-Response-Hop") != "" {
		t.Error("expected X-Response-Hop header to be removed from response")
	}
	if resp.Header.Get("Upgrade") != "" {
		t.Error("expected Upgrade header to be removed from response")
	}
	if resp.Header.Get("X-Response-Keep") != "true" {
		t.Error("expected X-Response-Keep header to be preserved")
	}
}

func TestProxyRenderer_RewritesHostHeader(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "upstream-host.com" {
			t.Errorf("expected Host 'upstream-host.com', got %q", r.Host)
		}
	}))
	defer upstream.Close()

	// We can't easily force httptest.Server to have a specific hostname without hacking DNS or /etc/hosts.
	// However, we can construct the ProxyRenderer with a fake target URL that has the hostname we want,
	// but then we need to trick the transport to dial the actual httptest server.
	//
	// Alternatively, and simpler: we just check that the Host header received by the upstream matches
	// the upstream's actual listener address (which NewProxyRenderer will use if we pass upstream.URL).
	//
	// Let's assume the incoming request has a different Host.

	// Parse upstream URL to get its host
	u, _ := url.Parse(upstream.URL)
	upstreamHost := u.Host

	// Re-create the upstream handler to close over upstreamHost
	upstream.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != upstreamHost {
			t.Errorf("expected Host %q, got %q", upstreamHost, r.Host)
		}
	})

	p, err := NewProxyRenderer(upstream.URL)
	if err != nil {
		t.Fatalf("failed to create renderer: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "original-client-host.com"

	if err := p.Render(rec, req); err != nil {
		t.Fatalf("Render failed: %v", err)
	}
}
