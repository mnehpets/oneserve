package endpoint

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStringRenderer_SetsContentTypeAndBody(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	r := StringRenderer{Body: "hello"}
	if err := r.Render(rec, req); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	resp := rec.Result()
	if got := resp.Header.Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("expected Content-Type %q, got %q", "text/plain; charset=utf-8", got)
	}
	if got := rec.Body.String(); got != "hello" {
		t.Fatalf("expected body %q, got %q", "hello", got)
	}
}

func TestStringRenderer_DoesNotOverrideExistingContentType(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec.Header().Set("Content-Type", "text/custom")

	r := StringRenderer{Body: "ok"}
	if err := r.Render(rec, req); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	resp := rec.Result()
	if got := resp.Header.Get("Content-Type"); got != "text/custom" {
		t.Fatalf("expected Content-Type %q, got %q", "text/custom", got)
	}
}

func TestStringRenderer_StatusOverride(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	r := StringRenderer{Status: http.StatusCreated, Body: "created"}
	if err := r.Render(rec, req); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	resp := rec.Result()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected status %d, got %d", http.StatusCreated, resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("expected Content-Type %q, got %q", "text/plain; charset=utf-8", got)
	}
	if got := rec.Body.String(); got != "created" {
		t.Fatalf("expected body %q, got %q", "created", got)
	}
}

func TestPlainRenderer_HelperUsesDefaultContentType(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	renderer := PlainRenderer{StringRenderer: StringRenderer{Body: "plain body"}}
	if err := renderer.Render(rec, req); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	resp := rec.Result()
	if got := resp.Header.Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("expected Content-Type %q, got %q", "text/plain; charset=utf-8", got)
	}
	if got := rec.Body.String(); got != "plain body" {
		t.Fatalf("expected body %q, got %q", "plain body", got)
	}
}

func TestHTMLRenderer_HelperSetsHTMLContentType(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	renderer := HTMLRenderer{StringRenderer: StringRenderer{Body: "<h1>hi</h1>"}}
	if err := renderer.Render(rec, req); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	resp := rec.Result()
	if got := resp.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("expected Content-Type %q, got %q", "text/html; charset=utf-8", got)
	}
	if got := rec.Body.String(); got != "<h1>hi</h1>" {
		t.Fatalf("expected body %q, got %q", "<h1>hi</h1>", got)
	}
}

func TestHTMLRenderer_DoesNotOverrideExistingContentType(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec.Header().Set("Content-Type", "text/custom")

	renderer := HTMLRenderer{StringRenderer: StringRenderer{Body: "<p>ok</p>"}}
	if err := renderer.Render(rec, req); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	resp := rec.Result()
	if got := resp.Header.Get("Content-Type"); got != "text/custom" {
		t.Fatalf("expected Content-Type %q, got %q", "text/custom", got)
	}
}

func TestRedirectRenderer_Redirects(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	r := RedirectRenderer{URL: "/new", Status: http.StatusMovedPermanently}
	if err := r.Render(rec, req); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	resp := rec.Result()
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("expected status %d, got %d", http.StatusMovedPermanently, resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "/new" {
		t.Fatalf("expected Location %q, got %q", "/new", got)
	}
}

func TestRedirectRenderer_DefaultStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	r := RedirectRenderer{URL: "/found"}
	if err := r.Render(rec, req); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	resp := rec.Result()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("expected status %d, got %d", http.StatusTemporaryRedirect, resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "/found" {
		t.Fatalf("expected Location %q, got %q", "/found", got)
	}
}
