package endpoint

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

type textUpper string

func (t *textUpper) UnmarshalText(b []byte) error {
	*t = textUpper(strings.ToUpper(string(b)))
	return nil
}

type decodeParams struct {
	ID    string   `path:"id"`
	Q     string   `query:"q"`
	N     int      `query:"n"`
	Ok    bool     `query:"ok"`
	Ratio float64  `query:"ratio"`
	P     *int     `query:"p"`
	F     string   `form:"f"`
	Limit uint     `form:"limit"`
	Flag  *bool    `form:"flag"`
	Score *float64 `form:"score"`
}

func TestUnmarshal_PathQueryForm(t *testing.T) {
	var p decodeParams
	var decodeErr error

	// Use net/http ServeMux path variables
	mux := http.NewServeMux()
	mux.HandleFunc("/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		decodeErr = Unmarshal(r, &p)
		w.WriteHeader(http.StatusOK)
	})

	body := strings.NewReader("f=x&limit=3&flag=true&score=1.25")
	req := httptest.NewRequest(http.MethodPost, "/users/42?q=hello&n=7&ok=true&ratio=0.5&p=9", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if decodeErr != nil {
		t.Fatalf("Unmarshal returned error: %v", decodeErr)
	}

	if p.ID != "42" {
		t.Fatalf("expected ID %q, got %q", "42", p.ID)
	}
	if p.Q != "hello" {
		t.Fatalf("expected Q %q, got %q", "hello", p.Q)
	}
	if p.N != 7 {
		t.Fatalf("expected N %d, got %d", 7, p.N)
	}
	if p.Ok != true {
		t.Fatalf("expected Ok %v, got %v", true, p.Ok)
	}
	if p.Ratio != 0.5 {
		t.Fatalf("expected Ratio %v, got %v", 0.5, p.Ratio)
	}
	if p.P == nil || *p.P != 9 {
		if p.P == nil {
			t.Fatalf("expected P non-nil")
		}
		t.Fatalf("expected P %d, got %d", 9, *p.P)
	}
	if p.F != "x" {
		t.Fatalf("expected F %q, got %q", "x", p.F)
	}
	if p.Limit != 3 {
		t.Fatalf("expected Limit %d, got %d", 3, p.Limit)
	}
	if p.Flag == nil || *p.Flag != true {
		if p.Flag == nil {
			t.Fatalf("expected Flag non-nil")
		}
		t.Fatalf("expected Flag %v, got %v", true, *p.Flag)
	}
	if p.Score == nil || *p.Score != 1.25 {
		if p.Score == nil {
			t.Fatalf("expected Score non-nil")
		}
		t.Fatalf("expected Score %v, got %v", 1.25, *p.Score)
	}
}

func TestUnmarshal_NonStructParams_ReturnsError(t *testing.T) {
	// Spec: params must be a non-nil pointer to a settable value; non-structs must error.
	var p int
	req := httptest.NewRequest(http.MethodGet, "/t", nil)
	if err := Unmarshal(req, &p); err == nil {
		t.Fatalf("expected error for non-struct dst, got nil")
	}
}

func TestUnmarshal_InterfaceParams_ReturnsError(t *testing.T) {
	// endpoint.Unmarshal requires dst to point to a struct (or pointer-to-struct).
	// Passing *any should be rejected (previously this was treated as a no-op).
	var p any
	req := httptest.NewRequest(http.MethodGet, "/t", nil)
	if err := Unmarshal(req, &p); err == nil {
		t.Fatalf("expected error for interface dst, got nil")
	}
}

func TestUnmarshal_MultipartForm(t *testing.T) {
	var p decodeParams
	var decodeErr error

	// Use net/http ServeMux path variables
	mux := http.NewServeMux()
	mux.HandleFunc("/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		decodeErr = Unmarshal(r, &p)
		w.WriteHeader(http.StatusOK)
	})

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	if err := w.WriteField("f", "x"); err != nil {
		t.Fatalf("WriteField f: %v", err)
	}
	if err := w.WriteField("limit", "3"); err != nil {
		t.Fatalf("WriteField limit: %v", err)
	}
	if err := w.WriteField("flag", "true"); err != nil {
		t.Fatalf("WriteField flag: %v", err)
	}
	if err := w.WriteField("score", "1.25"); err != nil {
		t.Fatalf("WriteField score: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("multipart close: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/users/42?q=hello&n=7&ok=true&ratio=0.5&p=9", &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if decodeErr != nil {
		t.Fatalf("Unmarshal returned error: %v", decodeErr)
	}

	if p.ID != "42" {
		t.Fatalf("expected ID %q, got %q", "42", p.ID)
	}
	if p.Q != "hello" {
		t.Fatalf("expected Q %q, got %q", "hello", p.Q)
	}
	if p.N != 7 {
		t.Fatalf("expected N %d, got %d", 7, p.N)
	}
	if p.Ok != true {
		t.Fatalf("expected Ok %v, got %v", true, p.Ok)
	}
	if p.Ratio != 0.5 {
		t.Fatalf("expected Ratio %v, got %v", 0.5, p.Ratio)
	}
	if p.P == nil || *p.P != 9 {
		if p.P == nil {
			t.Fatalf("expected P non-nil")
		}
		t.Fatalf("expected P %d, got %d", 9, *p.P)
	}
	if p.F != "x" {
		t.Fatalf("expected F %q, got %q", "x", p.F)
	}
	if p.Limit != 3 {
		t.Fatalf("expected Limit %d, got %d", 3, p.Limit)
	}
	if p.Flag == nil || *p.Flag != true {
		if p.Flag == nil {
			t.Fatalf("expected Flag non-nil")
		}
		t.Fatalf("expected Flag %v, got %v", true, *p.Flag)
	}
	if p.Score == nil || *p.Score != 1.25 {
		if p.Score == nil {
			t.Fatalf("expected Score non-nil")
		}
		t.Fatalf("expected Score %v, got %v", 1.25, *p.Score)
	}
}

func TestUnmarshal_MultipartForm_Files(t *testing.T) {
	type params struct {
		Files1 []*multipart.FileHeader `form:"files1"`
		Files2 []*multipart.FileHeader `form:"files2"`
		Note   string                  `form:"note"`
	}

	newReq := func() (*http.Request, map[string][]string) {
		var body bytes.Buffer
		w := multipart.NewWriter(&body)

		// Non-file field.
		if err := w.WriteField("note", "hello"); err != nil {
			t.Fatalf("WriteField note: %v", err)
		}

		// Two files in a single field.
		addFile := func(field, filename, contents string) {
			part, err := w.CreateFormFile(field, filename)
			if err != nil {
				t.Fatalf("CreateFormFile %s/%s: %v", field, filename, err)
			}
			if _, err := io.WriteString(part, contents); err != nil {
				t.Fatalf("write file %s/%s: %v", field, filename, err)
			}
		}
		addFile("files1", "a.txt", "aaa")
		addFile("files1", "b.txt", "bbbb")

		// Another field with a single file.
		addFile("files2", "c.txt", "cc")

		if err := w.Close(); err != nil {
			t.Fatalf("multipart close: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, "/t", &body)
		req.Header.Set("Content-Type", w.FormDataContentType())
		return req, map[string][]string{
			"files1": {"aaa", "bbbb"},
			"files2": {"cc"},
		}
	}

	checkFile := func(t *testing.T, fh *multipart.FileHeader, wantFilename, wantContents string) {
		t.Helper()
		if fh == nil {
			t.Fatalf("expected FileHeader non-nil")
		}
		if fh.Filename != wantFilename {
			t.Fatalf("expected filename %q, got %q", wantFilename, fh.Filename)
		}
		f, err := fh.Open()
		if err != nil {
			t.Fatalf("open %q: %v", fh.Filename, err)
		}
		defer f.Close()
		b, err := io.ReadAll(f)
		if err != nil {
			t.Fatalf("read %q: %v", fh.Filename, err)
		}
		if int64(len(b)) != fh.Size {
			t.Fatalf("expected size %d to match content len %d for %q", fh.Size, len(b), fh.Filename)
		}
		if string(b) != wantContents {
			t.Fatalf("expected contents %q, got %q for %q", wantContents, string(b), fh.Filename)
		}
	}

	req, _ := newReq()
	var p params
	if err := Unmarshal(req, &p); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}

	// Mixed field decoding.
	if p.Note != "hello" {
		t.Fatalf("expected note %q, got %q", "hello", p.Note)
	}

	// Multiple files in one field.
	if len(p.Files1) != 2 {
		t.Fatalf("expected Files1 length %d, got %d", 2, len(p.Files1))
	}
	checkFile(t, p.Files1[0], "a.txt", "aaa")
	checkFile(t, p.Files1[1], "b.txt", "bbbb")

	// Multiple fields with files.
	if len(p.Files2) != 1 {
		t.Fatalf("expected Files2 length %d, got %d", 1, len(p.Files2))
	}
	checkFile(t, p.Files2[0], "c.txt", "cc")
}

func TestUnmarshal_Body_JSON_Explicit(t *testing.T) {
	type params struct {
		Body struct {
			A string `json:"a"`
			N int    `json:"n"`
		} `body:",json"`
	}

	req := httptest.NewRequest(http.MethodPost, "/t", strings.NewReader(`{"a":"x","n":7}`))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	var p params
	if err := Unmarshal(req, &p); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if p.Body.A != "x" || p.Body.N != 7 {
		t.Fatalf("unexpected body: %+v", p.Body)
	}
}

func TestUnmarshal_Body_JSON_Explicit_ContentTypeMismatch(t *testing.T) {
	type params struct {
		Body map[string]any `body:",json"`
	}

	req := httptest.NewRequest(http.MethodPost, "/t", strings.NewReader(`{"a":1}`))
	req.Header.Set("Content-Type", "text/plain")

	var p params
	err := Unmarshal(req, &p)
	if err == nil {
		t.Fatalf("expected error")
	}
	if ee, ok := err.(*EndpointError); !ok || ee.Status != http.StatusUnsupportedMediaType {
		t.Fatalf("expected EndpointError 415, got %T %#v", err, err)
	}
}

func TestUnmarshal_Body_Default_String(t *testing.T) {
	type params struct {
		Body string `body:"placeholder"`
	}
	req := httptest.NewRequest(http.MethodPost, "/t", strings.NewReader("hello"))
	req.Header.Set("Content-Type", "text/plain")

	var p params
	if err := Unmarshal(req, &p); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if p.Body != "hello" {
		t.Fatalf("expected %q, got %q", "hello", p.Body)
	}
}

func TestUnmarshal_Body_Default_Bytes(t *testing.T) {
	type params struct {
		Body []byte `body:"placeholder"`
	}
	req := httptest.NewRequest(http.MethodPost, "/t", strings.NewReader("hello"))

	var p params
	if err := Unmarshal(req, &p); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if string(p.Body) != "hello" {
		t.Fatalf("expected %q, got %q", "hello", string(p.Body))
	}
}

func TestUnmarshal_Body_Precedence_FormBeatsBody_BodyBeatsCookie(t *testing.T) {
	type params struct {
		X string `form:"x" body:"x" cookie:"x"`
	}

	req := httptest.NewRequest(http.MethodPost, "/t", strings.NewReader("body"))
	req.Header.Set("Content-Type", "text/plain")
	req.AddCookie(&http.Cookie{Name: "x", Value: "cookie"})
	req.PostForm = url.Values{"x": []string{"form"}}
	req.Form = req.PostForm

	var p params
	if err := Unmarshal(req, &p); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if p.X != "form" {
		t.Fatalf("expected %q, got %q", "form", p.X)
	}
}

func TestUnmarshal_Body_MultipleFieldsError(t *testing.T) {
	type params struct {
		A string `body:"a"`
		B string `body:"b"`
	}
	req := httptest.NewRequest(http.MethodPost, "/t", strings.NewReader("x"))

	var p params
	err := Unmarshal(req, &p)
	if err == nil {
		t.Fatalf("expected error")
	}
	if ee, ok := err.(*EndpointError); !ok || ee.Status != http.StatusBadRequest {
		t.Fatalf("expected EndpointError 400, got %T %#v", err, err)
	}
}

func TestUnmarshal_Query_JSON_DecodesIntoStruct(t *testing.T) {
	type inner struct {
		A int `json:"a"`
	}
	type params struct {
		Q inner `query:"q,json"`
	}

	req := httptest.NewRequest(http.MethodGet, "/t?q=%7B%22a%22%3A123%7D", nil)

	var p params
	if err := Unmarshal(req, &p); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if p.Q.A != 123 {
		t.Fatalf("expected %d, got %d", 123, p.Q.A)
	}
}

func TestUnmarshal_Body_Default_JSON_DecodesIntoScalar(t *testing.T) {
	type params struct {
		N int `body:"n"`
	}

	req := httptest.NewRequest(http.MethodPost, "/t", strings.NewReader("123"))
	req.Header.Set("Content-Type", "application/json")

	var p params
	if err := Unmarshal(req, &p); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if p.N != 123 {
		t.Fatalf("expected %d, got %d", 123, p.N)
	}
}

func TestUnmarshal_MultipartForm_RootMaxLengthTag_SetsParseLimit(t *testing.T) {
	old := defaultFormLimit
	// Temporarily increase defaultFormLimit to 100MiB to ensure test only fails
	// if root tag is applied.
	defaultFormLimit = 100 << 20
	t.Cleanup(func() { defaultFormLimit = old })

	// Root tag should override defaultFormLimit.
	// Field F's maxLength is set to 20MB so that
	// the test does not trigger a field length error.
	var p struct {
		_ struct{} `maxLength:"64"`
		F string   `form:"f" maxLength:"204800000"`
	}

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	// Although we set the max form length to 64, multipart.Reader.readForm()
	// adds a buffer of 10MB, so make the form 11MB long to exceed that buffer.
	if err := w.WriteField("f", strings.Repeat("x", 11<<20)); err != nil {
		t.Fatalf("WriteField f: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("multipart close: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/t", &body)
	req.Header.Set("Content-Type", w.FormDataContentType())

	err := Unmarshal(req, &p)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
}

func TestUnmarshal_MultipartForm_RootMaxLengthTag_EmptyUsesDefault(t *testing.T) {
	// If tag exists but is empty, we should fall back to maxFormMemoryBytes.
	// This should succeed for a small form.
	var p struct {
		_ struct{} `maxLength:""`
		F string   `form:"f"`
	}

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	if err := w.WriteField("f", "x"); err != nil {
		t.Fatalf("WriteField f: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("multipart close: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/t", &body)
	req.Header.Set("Content-Type", w.FormDataContentType())

	if err := Unmarshal(req, &p); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if p.F != "x" {
		t.Fatalf("expected F %q, got %q", "x", p.F)
	}
}

func TestUnmarshal_PointerFieldsMissingRemainNil(t *testing.T) {
	var p decodeParams
	var decodeErr error

	mux := http.NewServeMux()
	mux.HandleFunc("/t/{id}", func(w http.ResponseWriter, r *http.Request) {
		decodeErr = Unmarshal(r, &p)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/t/abc?q=hi", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if decodeErr != nil {
		t.Fatalf("Unmarshal returned error: %v", decodeErr)
	}
	if p.P != nil {
		t.Fatalf("expected P nil, got %v", *p.P)
	}
	if p.Flag != nil {
		t.Fatalf("expected Flag nil, got %v", *p.Flag)
	}
	if p.Score != nil {
		t.Fatalf("expected Score nil, got %v", *p.Score)
	}
}

func TestUnmarshal_SourcePrecedence_PathOverridesQueryAndForm(t *testing.T) {
	// If a field is tagged for multiple sources, precedence is path -> query -> form.
	// This test uses a dedicated struct to validate that precedence.
	var p struct {
		V string `path:"v" query:"v" form:"v"`
	}
	var decodeErr error

	mux := http.NewServeMux()
	mux.HandleFunc("/p/{v}", func(w http.ResponseWriter, r *http.Request) {
		decodeErr = Unmarshal(r, &p)
		w.WriteHeader(http.StatusOK)
	})

	body := strings.NewReader("v=from-form")
	req := httptest.NewRequest(http.MethodPost, "/p/from-path?v=from-query", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if decodeErr != nil {
		t.Fatalf("Unmarshal returned error: %v", decodeErr)
	}
	if p.V != "from-path" {
		t.Fatalf("expected V %q, got %q", "from-path", p.V)
	}
}

func TestUnmarshal_JSONBody_NonStruct_String(t *testing.T) {
	// Spec: JSON body decoding is only supported when explicitly selected via a
	// `body`-tagged field.
	type params struct {
		Body string `body:",json"`
	}
	var p params
	req := httptest.NewRequest(http.MethodPost, "/t", strings.NewReader("\"hello\""))
	req.Header.Set("Content-Type", "application/json")

	if err := Unmarshal(req, &p); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if p.Body != "hello" {
		t.Fatalf("expected %q, got %q", "hello", p.Body)
	}
}

func TestUnmarshal_JSONBody_NonStruct_Int(t *testing.T) {
	// Spec: JSON body decoding is only supported when explicitly selected via a
	// `body`-tagged field.
	type params struct {
		Body int `body:",json"`
	}
	var p params
	req := httptest.NewRequest(http.MethodPost, "/t", strings.NewReader("123"))
	req.Header.Set("Content-Type", "application/json")

	if err := Unmarshal(req, &p); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if p.Body != 123 {
		t.Fatalf("expected %d, got %d", 123, p.Body)
	}
}

func TestUnmarshal_JSONBody_NonStruct_TypeMismatch_Is400(t *testing.T) {
	// Spec: JSON body decoding is only supported when explicitly selected via a
	// `body`-tagged field.
	type params struct {
		Body int `body:",json"`
	}
	var p params
	req := httptest.NewRequest(http.MethodPost, "/t", strings.NewReader("\"not-an-int\""))
	req.Header.Set("Content-Type", "application/json")

	err := Unmarshal(req, &p)
	if err == nil {
		t.Fatalf("expected error")
	}
	var ee *EndpointError
	if !errors.As(err, &ee) {
		t.Fatalf("expected *EndpointError, got %T: %v", err, err)
	}
	if ee.Status != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d (%v)", http.StatusBadRequest, ee.Status, err)
	}
}

func TestUnmarshal_Bytes_UTF8_Default(t *testing.T) {
	var p struct {
		B []byte `query:"b"`
	}
	var decodeErr error

	// no path params, just query
	mux := http.NewServeMux()
	mux.HandleFunc("/t", func(w http.ResponseWriter, r *http.Request) {
		decodeErr = Unmarshal(r, &p)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/t?b=hello", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Result().StatusCode)
	}
	if decodeErr != nil {
		t.Fatalf("Unmarshal returned error: %v", decodeErr)
	}
	if !bytes.Equal(p.B, []byte("hello")) {
		t.Fatalf("expected %q, got %q", "hello", string(p.B))
	}
}

func TestUnmarshal_Bytes_Base64(t *testing.T) {
	var p struct {
		B []byte `query:"b,base64"`
	}
	var decodeErr error

	plain := []byte("hello")
	encoded := base64.StdEncoding.EncodeToString(plain)

	mux := http.NewServeMux()

	mux.HandleFunc("/t", func(w http.ResponseWriter, r *http.Request) {
		decodeErr = Unmarshal(r, &p)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/t?b="+encoded, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Result().StatusCode)
	}
	if decodeErr != nil {
		t.Fatalf("Unmarshal returned error: %v", decodeErr)
	}
	if !bytes.Equal(p.B, plain) {
		t.Fatalf("expected %q, got %q", string(plain), string(p.B))
	}
}

func TestUnmarshal_Bytes_Base64URL(t *testing.T) {
	var p struct {
		B []byte `query:"b,base64url"`
	}
	var decodeErr error

	plain := []byte{0xff, 0x00, 0x10}
	encoded := base64.RawURLEncoding.EncodeToString(plain)

	mux := http.NewServeMux()

	mux.HandleFunc("/t", func(w http.ResponseWriter, r *http.Request) {
		decodeErr = Unmarshal(r, &p)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/t?b="+encoded, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Result().StatusCode)
	}
	if decodeErr != nil {
		t.Fatalf("Unmarshal returned error: %v", decodeErr)
	}
	if !bytes.Equal(p.B, plain) {
		t.Fatalf("expected %v, got %v", plain, p.B)
	}
}

func TestUnmarshal_EmptyTagValue_UsesFieldNameLowercased(t *testing.T) {
	var p struct {
		B string `query:","`
	}
	var decodeErr error

	mux := http.NewServeMux()
	mux.HandleFunc("/t", func(w http.ResponseWriter, r *http.Request) {
		decodeErr = Unmarshal(r, &p)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/t?b=hello", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Result().StatusCode)
	}
	if decodeErr != nil {
		t.Fatalf("Unmarshal returned error: %v", decodeErr)
	}
	if p.B != "hello" {
		t.Fatalf("expected B %q, got %q", "hello", p.B)
	}
}

func TestUnmarshal_MaxLength_ExceedingValue_ReturnsBadRequestError(t *testing.T) {
	var p struct {
		Q string `query:"q" maxLength:"5"`
	}
	var decodeErr error

	mux := http.NewServeMux()
	mux.HandleFunc("/t", func(w http.ResponseWriter, r *http.Request) {
		decodeErr = Unmarshal(r, &p)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/t?q=helloworld", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if decodeErr == nil {
		t.Fatalf("expected Unmarshal error")
	}
	var ee *EndpointError
	if !errors.As(decodeErr, &ee) {
		t.Fatalf("expected *EndpointError, got %T: %v", decodeErr, decodeErr)
	}
	if ee.Status != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, ee.Status)
	}
}

func TestUnmarshal_MaxLength_ExceedingBytesValue_ReturnsBadRequestError(t *testing.T) {
	var p struct {
		B []byte `query:"b,base64" maxLength:"8"`
	}
	var decodeErr error

	plain := []byte("hello")
	encoded := base64.StdEncoding.EncodeToString(plain) // "aGVsbG8=" (8 chars)

	mux := http.NewServeMux()
	mux.HandleFunc("/t", func(w http.ResponseWriter, r *http.Request) {
		decodeErr = Unmarshal(r, &p)
		w.WriteHeader(http.StatusOK)
	})

	// Add extra junk to prove truncation happens before decode.
	req := httptest.NewRequest(http.MethodGet, "/t?b="+encoded+"EXTRA", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if decodeErr == nil {
		t.Fatalf("expected Unmarshal error")
	}
	var ee *EndpointError
	if !errors.As(decodeErr, &ee) {
		t.Fatalf("expected *EndpointError, got %T: %v", decodeErr, decodeErr)
	}
	if ee.Status != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, ee.Status)
	}
}

func TestUnmarshal_MaxLength_InvalidValue_ReturnsError(t *testing.T) {
	var p struct {
		Q string `query:"q" maxLength:"nope"`
	}
	var decodeErr error

	mux := http.NewServeMux()
	mux.HandleFunc("/t", func(w http.ResponseWriter, r *http.Request) {
		decodeErr = Unmarshal(r, &p)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/t?q=hello", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if decodeErr == nil {
		t.Fatalf("expected Unmarshal error")
	}
}

func TestUnmarshal_DefaultFieldLimit_NoMaxLengthTag_TooLongValue_ReturnsBadRequest(t *testing.T) {
	var p struct {
		Q string `query:"q"`
	}
	var decodeErr error

	mux := http.NewServeMux()
	mux.HandleFunc("/t", func(w http.ResponseWriter, r *http.Request) {
		decodeErr = Unmarshal(r, &p)
		w.WriteHeader(http.StatusOK)
	})

	// No maxLength tag is present, so the default (16KB) limit should apply.
	// Use a value just over 16KB.
	tooLong := strings.Repeat("x", 16*1024+1)
	req := httptest.NewRequest(http.MethodGet, "/t?q="+url.QueryEscape(tooLong), nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if decodeErr == nil {
		t.Fatalf("expected Unmarshal error")
	}
	var ee *EndpointError
	if !errors.As(decodeErr, &ee) {
		t.Fatalf("expected *EndpointError, got %T: %v", decodeErr, decodeErr)
	}
	if ee.Status != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, ee.Status)
	}
}

func TestUnmarshal_SourceTag_IgnoreDash(t *testing.T) {
	var p struct {
		B string `query:","`
		X string `query:"-"`
	}
	var decodeErr error

	mux := http.NewServeMux()
	mux.HandleFunc("/t", func(w http.ResponseWriter, r *http.Request) {
		decodeErr = Unmarshal(r, &p)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/t?b=hello&x=should-not-set", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Result().StatusCode)
	}
	if decodeErr != nil {
		t.Fatalf("Unmarshal returned error: %v", decodeErr)
	}
	if p.B != "hello" {
		t.Fatalf("expected B %q, got %q", "hello", p.B)
	}
	if p.X != "" {
		t.Fatalf("expected X empty, got %q", p.X)
	}
}

func TestUnmarshal_UntaggedField_DefaultsToLowercaseAllSources(t *testing.T) {
	var p struct {
		Auto string
	}
	var decodeErr error

	mux := http.NewServeMux()
	mux.HandleFunc("/t/{auto}", func(w http.ResponseWriter, r *http.Request) {
		decodeErr = Unmarshal(r, &p)
		w.WriteHeader(http.StatusOK)
	})

	// Provide auto in all sources; path should win according to precedence
	// (path, query). Cookies and forms should be ignored for untagged fields.
	body := strings.NewReader("auto=from-form")
	req := httptest.NewRequest(http.MethodPost, "/t/from-path?auto=from-query", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "auto", Value: "from-cookie"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if decodeErr != nil {
		t.Fatalf("Unmarshal returned error: %v", decodeErr)
	}
	if p.Auto != "from-path" {
		t.Fatalf("expected Auto %q, got %q", "from-path", p.Auto)
	}

	// If ONLY form/cookie are provided for an untagged field, it should remain empty.
	p.Auto = ""
	req2 := httptest.NewRequest(http.MethodPost, "/t/none", strings.NewReader("auto=from-form"))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.AddCookie(&http.Cookie{Name: "auto", Value: "from-cookie"})
	// Note: We don't use the mux here so {auto} path var is not set.
	if err := Unmarshal(req2, &p); err != nil {
		t.Fatalf("Unmarshal req2: %v", err)
	}
	if p.Auto != "" {
		t.Fatalf("expected Auto empty when only form/cookie provided for untagged field, got %q", p.Auto)
	}
}

func TestUnmarshal_NestedStruct(t *testing.T) {
	var p struct {
		Inner struct {
			A string `query:"a"`
			B int
		}
		// Ensure sibling field still decodes.
		C bool `query:"c"`
	}
	var decodeErr error

	mux := http.NewServeMux()
	mux.HandleFunc("/t", func(w http.ResponseWriter, r *http.Request) {
		decodeErr = Unmarshal(r, &p)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/t?a=hello&b=7&c=true", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Result().StatusCode)
	}
	if decodeErr != nil {
		t.Fatalf("Unmarshal returned error: %v", decodeErr)
	}
	if p.Inner.A != "hello" {
		t.Fatalf("expected Inner.A %q, got %q", "hello", p.Inner.A)
	}
	if p.Inner.B != 7 {
		t.Fatalf("expected Inner.B %d, got %d", 7, p.Inner.B)
	}
	if p.C != true {
		t.Fatalf("expected C %v, got %v", true, p.C)
	}
}

func TestUnmarshal_JSONBodyDecodedAndOverriddenByPathAndQuery(t *testing.T) {
	var p struct {
		ID string `path:"id"`
		Q  string `query:"q"`
		// Untagged fields default to path then query (not body).
		X string `query:"x"`
		N int    `query:"n"`
	}
	var decodeErr error

	mux := http.NewServeMux()
	mux.HandleFunc("/t/{id}", func(w http.ResponseWriter, r *http.Request) {
		decodeErr = Unmarshal(r, &p)
		w.WriteHeader(http.StatusOK)
	})

	// Spec: body decoding is only applied via a `body`-tagged field, so this JSON
	// body should be ignored. Query/path values should win.
	body := strings.NewReader(`{"id":"json-id","q":"json-q","x":"from-json","n":1}`)
	req := httptest.NewRequest(http.MethodPost, "/t/path-id?q=query-q&n=7&x=from-query-x", body)
	req.Header.Set("Content-Type", "application/json")

	// Also provide form; but query should override only for N and Q and path for ID.
	req.PostForm = nil
	req.Form = nil

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if decodeErr != nil {
		t.Fatalf("Unmarshal returned error: %v", decodeErr)
	}
	if p.ID != "path-id" {
		t.Fatalf("expected ID %q, got %q", "path-id", p.ID)
	}
	if p.Q != "query-q" {
		t.Fatalf("expected Q %q, got %q", "query-q", p.Q)
	}
	if p.X != "from-query-x" {
		t.Fatalf("expected X %q, got %q", "from-query-x", p.X)
	}
	if p.N != 7 {
		t.Fatalf("expected N %d, got %d", 7, p.N)
	}
}

func FuzzUnmarshal_PathQueryBodyForm(f *testing.F) {
	// Seeds: cover empty, JSON, form, and invalid inputs.
	f.Add("", "", "", "")
	// JSON body: ensure JSON decoding path.
	f.Add("42", "q=hello&n=7", "application/json", `{"x":"from-json"}`)
	// Form body: ensure ParseForm path.
	f.Add("from-path", "q=from-query&n=123&b=_wAQ", "application/x-www-form-urlencoded", "f=from-form")
	// Invalid json.
	f.Add("bad", "n=not-an-int", "application/json", `{"x":`)

	f.Fuzz(func(t *testing.T, id string, rawQuery string, contentType string, body string) {
		// Prevent pathological sizes.
		if len(id) > 4096 || len(rawQuery) > 8192 || len(contentType) > 256 || len(body) > 1<<16 {
			t.Skip()
		}

		u := &url.URL{Path: "/t/" + url.PathEscape(id)}
		if rawQuery != "" {
			u.RawQuery = rawQuery
		}

		req := &http.Request{
			Method: http.MethodPost,
			URL:    u,
			Header: make(http.Header),
			Body:   io.NopCloser(strings.NewReader(body)),
		}
		// Fuzz Content-Type to steer body decoding/parsing.
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		// Attach a ServeMux-style path var for r.PathValue("id").
		req.SetPathValue("id", id)

		var p struct {
			ID string `path:"id"`
			Q  string `query:"q"`
			X  string
			N  int    `query:"n"`
			B  []byte `query:"b,base64url"`
			F  string `form:"f"`
		}
		err := Unmarshal(req, &p)
		if err != nil {
			// Fuzzing goal: no panics. Errors are fine.
			return
		}

		// Invariants:
		// - Path param wins over JSON for ID.
		if p.ID != id {
			t.Fatalf("expected ID %q, got %q", id, p.ID)
		}

		// - Query param wins over JSON for q/n when present.
		q := u.Query()
		if want := q.Get("q"); want != "" && p.Q != want {
			t.Fatalf("expected Q %q, got %q", want, p.Q)
		}
		if wantN := q.Get("n"); wantN != "" {
			// If n is present but not parseable, Unmarshal should have errored above.
			// So if we got here, it must match.
			if got := p.N; got != mustAtoi(t, wantN) {
				t.Fatalf("expected N %d, got %d", mustAtoi(t, wantN), got)
			}
		}

		// - If the request is form-encoded and has f, it should decode when decoding succeeds.
		//   (This is weaker than strict equality because ParseForm can fail on malformed bodies.)
		ct := strings.ToLower(strings.TrimSpace(contentType))
		if strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
			if wantF := req.FormValue("f"); wantF != "" && p.F != wantF {
				t.Fatalf("expected F %q, got %q", wantF, p.F)
			}
		}
	})
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	// strconv.Atoi has small, well-defined behavior; use it for invariant checking.
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("expected valid int %q: %v", s, err)
	}
	return n
}

func TestUnmarshal_TextUnmarshaler_CustomType(t *testing.T) {
	var p struct {
		V textUpper `query:"v"`
	}
	var decodeErr error

	mux := http.NewServeMux()
	mux.HandleFunc("/t", func(w http.ResponseWriter, r *http.Request) {
		decodeErr = Unmarshal(r, &p)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/t?v=hello", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if decodeErr != nil {
		t.Fatalf("Unmarshal returned error: %v", decodeErr)
	}
	if string(p.V) != "HELLO" {
		t.Fatalf("expected V %q, got %q", "HELLO", string(p.V))
	}
}

func TestUnmarshal_TextUnmarshaler_TimeTime(t *testing.T) {
	var p struct {
		T time.Time `query:"t"`
	}
	var decodeErr error

	mux := http.NewServeMux()
	mux.HandleFunc("/t", func(w http.ResponseWriter, r *http.Request) {
		decodeErr = Unmarshal(r, &p)
		w.WriteHeader(http.StatusOK)
	})

	// Use Go's "magic" reference date/time.
	// RFC3339 is time.Time's text format.
	want := time.Date(2006, 1, 2, 15, 4, 5, 0, time.FixedZone("UTC+7", 7*60*60))
	req := httptest.NewRequest(http.MethodGet, "/t?t="+url.QueryEscape(want.Format(time.RFC3339)), nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if decodeErr != nil {
		t.Fatalf("Unmarshal returned error: %v", decodeErr)
	}
	if !p.T.Equal(want) {
		t.Fatalf("expected T %v, got %v", want, p.T)
	}
}

func TestUnmarshal_Cookie_Basic(t *testing.T) {
	var p struct {
		Session string `cookie:"session"`
		Auto    string `cookie:""`
	}
	var decodeErr error

	mux := http.NewServeMux()
	mux.HandleFunc("/t", func(w http.ResponseWriter, r *http.Request) {
		decodeErr = Unmarshal(r, &p)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/t", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "abc"})
	req.AddCookie(&http.Cookie{Name: "auto", Value: "zzz"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if decodeErr != nil {
		t.Fatalf("Unmarshal returned error: %v", decodeErr)
	}
	if p.Session != "abc" {
		t.Fatalf("expected Session %q, got %q", "abc", p.Session)
	}
	// Untagged fields default to lowercased name across all sources; ensure cookies participate.
	if p.Auto != "zzz" {
		t.Fatalf("expected Auto %q, got %q", "zzz", p.Auto)
	}
}

func TestUnmarshal_Cookie_Missing_RemainsZero(t *testing.T) {
	var p struct {
		Session string `cookie:"session"`
	}
	var decodeErr error

	mux := http.NewServeMux()
	mux.HandleFunc("/t", func(w http.ResponseWriter, r *http.Request) {
		decodeErr = Unmarshal(r, &p)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/t", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if decodeErr != nil {
		t.Fatalf("Unmarshal returned error: %v", decodeErr)
	}
	if p.Session != "" {
		t.Fatalf("expected Session empty, got %q", p.Session)
	}
}

func TestUnmarshal_Cookie_Precedence_QueryOverridesCookie(t *testing.T) {
	var p struct {
		V string `query:"v" cookie:"v"`
	}
	var decodeErr error

	mux := http.NewServeMux()
	mux.HandleFunc("/t", func(w http.ResponseWriter, r *http.Request) {
		decodeErr = Unmarshal(r, &p)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/t?v=from-query", nil)
	req.AddCookie(&http.Cookie{Name: "v", Value: "from-cookie"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if decodeErr != nil {
		t.Fatalf("Unmarshal returned error: %v", decodeErr)
	}
	if p.V != "from-query" {
		t.Fatalf("expected V %q, got %q", "from-query", p.V)
	}
}

func TestUnmarshal_Cookie_URLescapedValue_RemainsEscapedString(t *testing.T) {
	var p struct {
		V string `cookie:"v"`
	}
	var decodeErr error

	mux := http.NewServeMux()
	mux.HandleFunc("/t", func(w http.ResponseWriter, r *http.Request) {
		decodeErr = Unmarshal(r, &p)
		w.WriteHeader(http.StatusOK)
	})

	// net/http does not automatically URL-decode Cookie.Value here.
	req := httptest.NewRequest(http.MethodGet, "/t", nil)
	req.AddCookie(&http.Cookie{Name: "v", Value: "hello%20world"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if decodeErr != nil {
		t.Fatalf("Unmarshal returned error: %v", decodeErr)
	}
	if p.V != "hello%20world" {
		t.Fatalf("expected V %q, got %q", "hello%20world", p.V)
	}
}

func TestUnmarshal_Body_JSON_Explicit_ContentTypeMismatch_StringField(t *testing.T) {
	type params struct {
		Body string `body:",json"`
	}

	req := httptest.NewRequest(http.MethodPost, "/t", strings.NewReader(`"hello"`))
	req.Header.Set("Content-Type", "text/plain")

	var p params
	err := Unmarshal(req, &p)
	if err == nil {
		t.Fatalf("expected error for string field with json encoding and wrong content type")
	}
	if ee, ok := err.(*EndpointError); !ok || ee.Status != http.StatusUnsupportedMediaType {
		t.Fatalf("expected EndpointError 415, got %T %#v", err, err)
	}
}

func TestUnmarshal_Base64_OnNonByteField_ReturnsError(t *testing.T) {
	var p struct {
		S string `query:"s,base64"`
	}
	req := httptest.NewRequest(http.MethodGet, "/t?s=aGVsbG8=", nil) // "hello" in base64

	err := Unmarshal(req, &p)
	if err == nil {
		t.Fatalf("expected error when using base64 on string field, got nil")
	}
	var ee *EndpointError
	if !errors.As(err, &ee) {
		t.Fatalf("expected *EndpointError, got %T: %v", err, err)
	}
	// The spec says "Unmarshal MUST return a non-nil error".
	// Since this is a schema definition issue (invalid tag usage for the type),
	// 500 Internal Server Error is appropriate (consistent with other tag errors).
	if ee.Status != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", ee.Status)
	}
}

func TestUnmarshal_Header_Basic(t *testing.T) {
	var p struct {
		Auth string `header:"Authorization"`
		User string `header:"X-User"`
	}
	var decodeErr error

	mux := http.NewServeMux()
	mux.HandleFunc("/t", func(w http.ResponseWriter, r *http.Request) {
		decodeErr = Unmarshal(r, &p)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/t", nil)
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("X-User", "alice")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if decodeErr != nil {
		t.Fatalf("Unmarshal returned error: %v", decodeErr)
	}
	if p.Auth != "Bearer token" {
		t.Fatalf("expected Auth %q, got %q", "Bearer token", p.Auth)
	}
	if p.User != "alice" {
		t.Fatalf("expected User %q, got %q", "alice", p.User)
	}
}

func TestUnmarshal_Header_Precedence(t *testing.T) {
	// Header has lowest precedence: path -> query -> form -> body -> cookie -> header
	var p struct {
		V string `cookie:"v" header:"v"`
	}
	var decodeErr error

	mux := http.NewServeMux()
	mux.HandleFunc("/t", func(w http.ResponseWriter, r *http.Request) {
		decodeErr = Unmarshal(r, &p)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/t", nil)
	req.Header.Set("v", "from-header")
	req.AddCookie(&http.Cookie{Name: "v", Value: "from-cookie"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if decodeErr != nil {
		t.Fatalf("Unmarshal returned error: %v", decodeErr)
	}
	if p.V != "from-cookie" {
		t.Fatalf("expected V %q, got %q", "from-cookie", p.V)
	}
}

func TestUnmarshal_Slice_Query(t *testing.T) {
	var p struct {
		IDs []int `query:"id"`
	}
	var decodeErr error

	mux := http.NewServeMux()
	mux.HandleFunc("/t", func(w http.ResponseWriter, r *http.Request) {
		decodeErr = Unmarshal(r, &p)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/t?id=1&id=2&id=3", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if decodeErr != nil {
		t.Fatalf("Unmarshal returned error: %v", decodeErr)
	}
	if len(p.IDs) != 3 {
		t.Fatalf("expected 3 IDs, got %d", len(p.IDs))
	}
	if p.IDs[0] != 1 || p.IDs[1] != 2 || p.IDs[2] != 3 {
		t.Fatalf("unexpected IDs: %v", p.IDs)
	}
}

func TestUnmarshal_Slice_Header(t *testing.T) {
	var p struct {
		Values []string `header:"X-Val"`
	}
	var decodeErr error

	mux := http.NewServeMux()
	mux.HandleFunc("/t", func(w http.ResponseWriter, r *http.Request) {
		decodeErr = Unmarshal(r, &p)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/t", nil)
	req.Header.Add("X-Val", "foo")
	req.Header.Add("X-Val", "bar")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if decodeErr != nil {
		t.Fatalf("Unmarshal returned error: %v", decodeErr)
	}
	if len(p.Values) != 2 {
		t.Fatalf("expected 2 Values, got %d", len(p.Values))
	}
	if p.Values[0] != "foo" || p.Values[1] != "bar" {
		t.Fatalf("unexpected Values: %v", p.Values)
	}
}

func TestUnmarshal_Slice_Cookie(t *testing.T) {
	var p struct {
		Tokens []string `cookie:"token"`
	}
	var decodeErr error

	mux := http.NewServeMux()
	mux.HandleFunc("/t", func(w http.ResponseWriter, r *http.Request) {
		decodeErr = Unmarshal(r, &p)
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/t", nil)
	req.AddCookie(&http.Cookie{Name: "token", Value: "a"})
	req.AddCookie(&http.Cookie{Name: "token", Value: "b"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if decodeErr != nil {
		t.Fatalf("Unmarshal returned error: %v", decodeErr)
	}
	if len(p.Tokens) != 2 {
		t.Fatalf("expected 2 Tokens, got %d", len(p.Tokens))
	}
	if p.Tokens[0] != "a" || p.Tokens[1] != "b" {
		t.Fatalf("unexpected Tokens: %v", p.Tokens)
	}
}

func TestUnmarshal_Slice_JSON_Override(t *testing.T) {
	// If json encoding is specified, we should decode the first value as a JSON blob,
	// NOT iterate over values.
	var p struct {
		List []int `query:"list,json"`
	}
	var decodeErr error

	mux := http.NewServeMux()
	mux.HandleFunc("/t", func(w http.ResponseWriter, r *http.Request) {
		decodeErr = Unmarshal(r, &p)
		w.WriteHeader(http.StatusOK)
	})

	// ?list=[1,2,3]
	// If it were treating list as repeated params, it would see one value "[1,2,3]" and try to decode that into []int,
	// which presumably fails if it tried to parse "[1,2,3]" as an int.
	// But with json, it should just unmarshal that string into the slice.
	req := httptest.NewRequest(http.MethodGet, "/t?list=%5B1%2C2%2C3%5D", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if decodeErr != nil {
		t.Fatalf("Unmarshal returned error: %v", decodeErr)
	}
	if len(p.List) != 3 {
		t.Fatalf("expected 3 items, got %d", len(p.List))
	}
	if p.List[0] != 1 || p.List[2] != 3 {
		t.Fatalf("unexpected List: %v", p.List)
	}
}

func TestUnmarshal_Slice_ResetsExisting(t *testing.T) {
	// Spec: Unmarshal MUST reset the slice to length 0 (if initialized) and then append.
	var p struct {
		IDs []int `query:"id"`
	}
	// Initialize with existing data.
	p.IDs = []int{10, 20, 30}

	mux := http.NewServeMux()
	mux.HandleFunc("/t", func(w http.ResponseWriter, r *http.Request) {
		if err := Unmarshal(r, &p); err != nil {
			t.Errorf("Unmarshal error: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/t?id=1&id=2", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if len(p.IDs) != 2 {
		t.Fatalf("expected 2 IDs, got %d", len(p.IDs))
	}
	if p.IDs[0] != 1 || p.IDs[1] != 2 {
		t.Fatalf("unexpected IDs: %v", p.IDs)
	}
}
