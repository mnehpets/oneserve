package endpoint

import (
	htmltmpl "html/template"
	"net/http"
	"net/http/httptest"
	"testing"
	texttmpl "text/template"
)

func TestTextTemplateRenderer_Execute(t *testing.T) {
	tmpl := texttmpl.Must(texttmpl.New("base").Parse("hello {{.Name}}"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	renderer := TextTemplateRenderer{Template: tmpl, Values: map[string]string{"Name": "world"}}
	if err := renderer.Render(rec, req); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	resp := rec.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("expected Content-Type %q, got %q", "text/plain; charset=utf-8", got)
	}
	if got := rec.Body.String(); got != "hello world" {
		t.Fatalf("expected body %q, got %q", "hello world", got)
	}
}

func TestTextTemplateRenderer_ExecuteTemplateByName(t *testing.T) {
	tmpl := texttmpl.Must(texttmpl.New("one").Parse("ONE"))
	texttmpl.Must(tmpl.New("two").Parse("TWO"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	renderer := TextTemplateRenderer{Template: tmpl, Name: "two"}
	if err := renderer.Render(rec, req); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}
	if got := rec.Body.String(); got != "TWO" {
		t.Fatalf("expected body %q, got %q", "TWO", got)
	}
}

func TestTextTemplateRenderer_DoesNotOverrideExistingContentType(t *testing.T) {
	tmpl := texttmpl.Must(texttmpl.New("base").Parse("ok"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec.Header().Set("Content-Type", "text/custom")

	renderer := TextTemplateRenderer{Template: tmpl}
	if err := renderer.Render(rec, req); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	resp := rec.Result()
	if got := resp.Header.Get("Content-Type"); got != "text/custom" {
		t.Fatalf("expected Content-Type %q, got %q", "text/custom", got)
	}
}

func TestHTMLTemplateRenderer_Execute(t *testing.T) {
	tmpl := htmltmpl.Must(htmltmpl.New("base").Parse("<p>{{.Name}}</p>"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	renderer := HTMLTemplateRenderer{Template: tmpl, Values: map[string]string{"Name": "ok"}}
	if err := renderer.Render(rec, req); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	resp := rec.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("expected Content-Type %q, got %q", "text/html; charset=utf-8", got)
	}
	if got := rec.Body.String(); got != "<p>ok</p>" {
		t.Fatalf("expected body %q, got %q", "<p>ok</p>", got)
	}
}

func TestHTMLTemplateRenderer_ExecuteTemplateByName(t *testing.T) {
	tmpl := htmltmpl.Must(htmltmpl.New("one").Parse("<b>ONE</b>"))
	htmltmpl.Must(tmpl.New("two").Parse("<i>TWO</i>"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	renderer := HTMLTemplateRenderer{Template: tmpl, Name: "two"}
	if err := renderer.Render(rec, req); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}
	if got := rec.Body.String(); got != "<i>TWO</i>" {
		t.Fatalf("expected body %q, got %q", "<i>TWO</i>", got)
	}
}

func TestHTMLTemplateRenderer_DoesNotOverrideExistingContentType(t *testing.T) {
	tmpl := htmltmpl.Must(htmltmpl.New("base").Parse("ok"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec.Header().Set("Content-Type", "text/custom")

	renderer := HTMLTemplateRenderer{Template: tmpl}
	if err := renderer.Render(rec, req); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	resp := rec.Result()
	if got := resp.Header.Get("Content-Type"); got != "text/custom" {
		t.Fatalf("expected Content-Type %q, got %q", "text/custom", got)
	}
}

func TestTemplateRenderers_NilTemplate_IsError(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	if err := (&TextTemplateRenderer{}).Render(rec, req); err == nil {
		t.Fatalf("expected error")
	}
	if err := (&HTMLTemplateRenderer{}).Render(rec, req); err == nil {
		t.Fatalf("expected error")
	}
}

func TestTemplateRenderers_ExecuteError_IsReturned(t *testing.T) {
	tmpl := texttmpl.Must(texttmpl.New("base").Parse("{{ template \"missing\" . }}"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	err := (&TextTemplateRenderer{Template: tmpl}).Render(rec, req)
	if err == nil {
		t.Fatalf("expected error")
	}
}



func TestHandler_TextTemplateRenderer_ExecuteError_Is500(t *testing.T) {
	// Missing named template produces an execution error.
	tmpl := texttmpl.Must(texttmpl.New("base").Parse("{{ template \"missing\" . }}"))

	mux := http.NewServeMux()
	mux.Handle("/t", Handler(func(_ http.ResponseWriter, _ *http.Request, params struct{}) (Renderer, error) {
		return &TextTemplateRenderer{Template: tmpl, Values: params}, nil
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/t", nil)
	mux.ServeHTTP(rec, req)

	if rec.Result().StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, rec.Result().StatusCode)
	}
}

func TestHandler_HTMLTemplateRenderer_ExecuteError_Is500(t *testing.T) {
	// Referencing a missing field produces an execution error.
	tmpl := htmltmpl.Must(htmltmpl.New("base").Parse("{{.MissingField}}"))
	mux := http.NewServeMux()
	mux.Handle("/t", Handler(func(_ http.ResponseWriter, _ *http.Request, params struct{}) (Renderer, error) {
		return &HTMLTemplateRenderer{Template: tmpl, Values: params}, nil
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/t", nil)
	mux.ServeHTTP(rec, req)

	if rec.Result().StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, rec.Result().StatusCode)
	}
}

func TestHandler_TemplateRenderer_ParamDecodeError_Is4xx(t *testing.T) {
	tmpl := texttmpl.Must(texttmpl.New("base").Parse("{{.MissingField}}"))

	mux := http.NewServeMux()
	mux.Handle("/t", Handler(func(_ http.ResponseWriter, _ *http.Request, params struct {
		N int `query:"n"`
	}) (Renderer, error) {
		return &TextTemplateRenderer{Template: tmpl, Values: nil}, nil
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/t?n=not-an-int", nil)
	mux.ServeHTTP(rec, req)

	if rec.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rec.Result().StatusCode)
	}
}
