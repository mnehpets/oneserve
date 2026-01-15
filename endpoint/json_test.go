package endpoint

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var errSentinel = errors.New("json encode error")

type jsonBadValue struct{}

func (jsonBadValue) MarshalJSON() ([]byte, error) {
	return nil, errSentinel
}

func TestJSONRenderer_SetsContentTypeAndEncodesBody(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	r := JSONRenderer{Value: map[string]string{"hello": "world"}}
	if err := r.Render(rec, req); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	resp := rec.Result()
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("expected Content-Type %q, got %q", "application/json", got)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
	// json.Encoder adds a trailing newline.
	if got := rec.Body.String(); got != "{\"hello\":\"world\"}\n" {
		t.Fatalf("expected body %q, got %q", "{\"hello\":\"world\"}\\n", got)
	}
}

func TestJSONRenderer_DoesNotOverrideExistingContentType(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Set("Content-Type", "application/vnd.api+json")
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	r := JSONRenderer{Value: map[string]bool{"ok": true}}
	if err := r.Render(rec, req); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	resp := rec.Result()
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("expected Content-Type %q, got %q", "application/json", got)
	}
}

func TestJSONRenderer_EncodeError_ReturnsError(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	r := JSONRenderer{Value: jsonBadValue{}}
	err := r.Render(rec, req)
	if err == nil {
		t.Fatalf("expected error")
	}
	var me *json.MarshalerError
	if !errors.As(err, &me) {
		t.Fatalf("expected *json.MarshalerError, got %T (%v)", err, err)
	}
	if unwrapped := errors.Unwrap(err); unwrapped != errSentinel {
		t.Fatalf("expected errors.Unwrap(err) == %v, got %v", errSentinel, unwrapped)
	}

	resp := rec.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
	// On encoding failure, body may be partially written; but should not contain
	// our value.
	if strings.Contains(rec.Body.String(), "hello") {
		t.Fatalf("unexpected body content: %q", rec.Body.String())
	}
}

func TestJSONRenderer_EncoderFactory_AllowsEscapeHTMLTrue(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	r := JSONRenderer{
		Value: map[string]string{"html": "<b>&</b>"},
		EncoderFactory: func(w io.Writer) *json.Encoder {
			enc := json.NewEncoder(w)
			enc.SetEscapeHTML(true)
			return enc
		},
	}

	if err := r.Render(rec, req); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	// When EscapeHTML is true, '<', '>', and '&' are escaped.
	got := rec.Body.String()
	if !strings.Contains(got, "\\u003c") || !strings.Contains(got, "\\u003e") || !strings.Contains(got, "\\u0026") {
		t.Fatalf("expected HTML escapes in JSON output, got %q", got)
	}
}
