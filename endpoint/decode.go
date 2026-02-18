package endpoint

import (
	"bytes"
	"encoding"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
)

// defaultFormLimit is the maximum amount of memory to use when parsing
// multipart form data. Anything beyond this may be stored in temporary files by
// net/http.
//
// This is a var (not const) so tests/callers can override it if needed.
var defaultFormLimit int64 = 32 << 20 // 32MB
var defaultFieldLimit int = 16 * 1024 // 16KB

// Unmarshal populates dst (must be a non-nil pointer) from the request.
//
// Supported sources in this implementation:
//   - path params: r.PathValue()
//   - query params: r.URL.Query()
//   - form params: r.Form / r.PostForm (ParseForm is called as needed)
//   - request body: r.Body (via `body` tag)
//   - headers: r.Header (via `header` tag)
//   - cookies: r.Cookie(name)
//
// Supported structtags:
//   - `path:"name[,flag[,flag...]]"`
//   - `query:"name[,flag[,flag...]]"`
//   - `form:"name[,flag[,flag...]]"`
//   - `body:"name[,flag[,flag...]]"`
//   - `header:"name[,flag[,flag...]]"`
//   - `cookie:"name[,flag[,flag...]]"`
//   - `path:"-"` to ignore the field entirely
//   - `maxLength:"n"` to set the maximum byte length for a field value
//
// Where:
//   - name: parameter name; if empty, defaults to the struct field name lowercased
//   - flag(s): optional
//   - []byte decoding: base64 | base64url
//   - json decoding: json (supported for all sources)
//
// Notes:
//   - Each of path/query/form/body/cookie tags is independent; you may specify different param names and
//     different []byte decoding flags per source.
//   - If multiple source tags are present on the same field, precedence is: path, query, form, body, cookie.
//   - If no data is present for a field, it is left unchanged (zero-value by default).
//
// Length constraints:
//   - Individual fields: use `maxLength:"n"` to set a maximum byte length for the field value.
//     If the incoming value exceeds this limit, Unmarshal returns a 400 Bad Request error.
//     If `maxLength` is absent, a default limit of 16KB (16384 bytes) is enforced.
//     Use `maxLength:"0"` or `maxLength:""` for no limit.
//   - Multipart form parsing: use `maxLength:"n"` on a root-level `_` field to set the
//     maximum memory (in bytes) for ParseMultipartForm. If absent, defaults to 32MB.
func Unmarshal(r *http.Request, dst any) error {
	if r == nil {
		return newEndpointError(http.StatusInternalServerError, "", errors.New("endpoint: decode: nil request"))
	}
	v := reflect.ValueOf(dst)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return newEndpointError(http.StatusInternalServerError, "", errors.New("endpoint: decode: dst must be a non-nil pointer"))
	}

	// Support *P where P may be a struct or pointer-to-struct.
	root := v.Elem()
	if root.Kind() == reflect.Pointer {
		if root.IsNil() {
			root.Set(reflect.New(root.Type().Elem()))
		}
		root = root.Elem()
	}

	// Require struct params for decoding.
	if root.Kind() != reflect.Struct {
		return newEndpointError(http.StatusInternalServerError, "", errors.New("endpoint: decode: dst must point to a struct (or pointer to struct)"))
	}

	q := url.Values{}
	if r.URL != nil {
		q = r.URL.Query()
	}

	form := url.Values{}
	files := map[string][]*multipart.FileHeader(nil)
	if !requestBodyIsJSON(r) {
		formLimit := defaultFormLimit
		if ml, ok, err := maxFormLengthBytes(root.Type()); err != nil {
			return newEndpointError(http.StatusInternalServerError, "", err)
		} else if ok {
			formLimit = ml
		}

		f, mf, err := parseRequestFormValues(r, formLimit)
		if err != nil {
			return err
		}
		form = f
		files = mf
	}

	if err := unmarshalStruct(r, root, q, form, files); err != nil {
		return err
	}
	return nil
}

// maxFormLengthBytes returns the max multipart form memory to use.
//
// If the root struct has a field named "_" and that field has a struct tag
// `maxLength:"<n>"`, that value is used.
//
// ok is true if the "_" field existed (even if tag is empty). If tag is absent
// or empty, the caller should apply a default.
func maxFormLengthBytes(rootType reflect.Type) (maxLen int64, ok bool, err error) {
	if rootType == nil {
		return 0, false, nil
	}
	if rootType.Kind() != reflect.Struct {
		return 0, false, nil
	}

	sf, exists := rootType.FieldByName("_")
	if !exists {
		return 0, false, nil
	}
	// Field exists, even if unexported ("_") and never set.
	ok = true

	tag := strings.TrimSpace(sf.Tag.Get("maxLength"))
	if tag == "" {
		return 0, ok, nil
	}
	v, perr := strconv.ParseInt(tag, 10, 64)
	if perr != nil {
		return 0, ok, fmt.Errorf("endpoint: decode: root maxLength tag: %w", perr)
	}
	if v < 0 {
		return 0, ok, fmt.Errorf("endpoint: decode: root maxLength tag must be non-negative")
	}
	return v, ok, nil
}

func requestBodyIsJSON(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.Body == nil || r.Body == http.NoBody {
		return false
	}
	mt := requestBodyMediaType(r)
	if mt == "" {
		return false
	}
	if strings.HasPrefix(mt, "application/json") {
		return true
	}
	return strings.HasSuffix(mt, "+json")
}

func requestBodyMediaType(r *http.Request) string {
	if r == nil {
		return ""
	}
	ct := strings.TrimSpace(r.Header.Get("Content-Type"))
	if ct == "" {
		return ""
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		// If malformed, return the raw (lowercased) content-type.
		return strings.ToLower(strings.TrimSpace(ct))
	}
	return strings.ToLower(strings.TrimSpace(mt))
}

func parseRequestFormValues(r *http.Request, formLimit int64) (url.Values, map[string][]*multipart.FileHeader, error) {
	if r == nil {
		return url.Values{}, nil, newEndpointError(http.StatusInternalServerError, "", errors.New("endpoint: decode: nil request"))
	}
	ct := strings.TrimSpace(r.Header.Get("Content-Type"))
	mediaType := "application/x-www-form-urlencoded"
	if ct != "" {
		mt, _, err := mime.ParseMediaType(ct)
		if err != nil {
			// Malformed content type.
			return url.Values{}, nil, newEndpointError(http.StatusBadRequest, "", fmt.Errorf("parse content-type: %w", err))
		}
		mediaType = strings.ToLower(strings.TrimSpace(mt))
	}

	switch mediaType {
	case "application/x-www-form-urlencoded":
		if err := r.ParseForm(); err != nil {
			return url.Values{}, nil, newEndpointError(http.StatusBadRequest, "", fmt.Errorf("parse form: %w", err))
		}
		return r.Form, nil, nil
	case "multipart/form-data":
		// ParseMultipartForm parses both query and multipart body form fields.
		// We return both text values and file headers.
		if err := r.ParseMultipartForm(formLimit); err != nil {
			return url.Values{}, nil, newEndpointError(http.StatusBadRequest, "", fmt.Errorf("parse multipart form: %w", err))
		}
		if r.MultipartForm == nil {
			return url.Values{}, nil, nil
		}
		// url.Values is map[string][]string, same underlying type as MultipartForm.Value.
		return url.Values(r.MultipartForm.Value), r.MultipartForm.File, nil
	default:
		// For other types (including GET/HEAD, empty body, etc.), keep ParseForm behavior.
		if err := r.ParseForm(); err != nil {
			return url.Values{}, nil, newEndpointError(http.StatusBadRequest, "", fmt.Errorf("parse form: %w", err))
		}
		return r.Form, nil, nil
	}
}

func unmarshalStruct(r *http.Request, structVal reflect.Value, query url.Values, form url.Values, files map[string][]*multipart.FileHeader) error {
	t := structVal.Type()
	var bodyFieldIndex = -1
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		if sf.PkgPath != "" { // unexported
			continue
		}
		fv := structVal.Field(i)

		defaultName := strings.ToLower(sf.Name)

		// Parse tags for each source.
		pathTag, hasPath, err := parseSourceTag(sf, "path", defaultName)
		if err != nil {
			return newEndpointError(http.StatusInternalServerError, "", fmt.Errorf("endpoint: decode: field %s: %w", sf.Name, err))
		}
		queryTag, hasQuery, err := parseSourceTag(sf, "query", defaultName)
		if err != nil {
			return newEndpointError(http.StatusInternalServerError, "", fmt.Errorf("endpoint: decode: field %s: %w", sf.Name, err))
		}
		bodyTag, hasBody, err := parseSourceTag(sf, "body", defaultName)
		if err != nil {
			return newEndpointError(http.StatusInternalServerError, "", fmt.Errorf("endpoint: decode: field %s: %w", sf.Name, err))
		}
		cookieTag, hasCookie, err := parseSourceTag(sf, "cookie", defaultName)
		if err != nil {
			return newEndpointError(http.StatusInternalServerError, "", fmt.Errorf("endpoint: decode: field %s: %w", sf.Name, err))
		}
		formTag, hasForm, err := parseSourceTag(sf, "form", defaultName)
		if err != nil {
			return newEndpointError(http.StatusInternalServerError, "", fmt.Errorf("endpoint: decode: field %s: %w", sf.Name, err))
		}
		headerTag, hasHeader, err := parseSourceTag(sf, "header", defaultName)
		if err != nil {
			return newEndpointError(http.StatusInternalServerError, "", fmt.Errorf("endpoint: decode: field %s: %w", sf.Name, err))
		}

		// Track the single supported body field.
		if hasBody && bodyTag.Name != "-" {
			if bodyFieldIndex != -1 {
				return newEndpointError(http.StatusBadRequest, "", fmt.Errorf("endpoint: decode: multiple body fields: %s and %s", t.Field(bodyFieldIndex).Name, sf.Name))
			}
			bodyFieldIndex = i
		}

		// Check for ignore tag.
		if (hasPath && pathTag.Name == "-") || (hasQuery && queryTag.Name == "-") || (hasBody && bodyTag.Name == "-") || (hasCookie && cookieTag.Name == "-") || (hasForm && formTag.Name == "-") || (hasHeader && headerTag.Name == "-") {
			continue
		}

		hasAnyTag := hasPath || hasQuery || hasBody || hasCookie || hasForm || hasHeader

		// Untagged, non-struct fields default to path then query with lower-case field name.
		isNonStructField := sf.Type.Kind() != reflect.Struct
		if sf.Type.Kind() == reflect.Pointer {
			isNonStructField = sf.Type.Elem().Kind() != reflect.Struct
		}
		if !hasAnyTag && isNonStructField {
			hasPath = true
			hasQuery = true
			pathTag = sourceTag{Source: "path", Name: defaultName, Encoding: ""}
			queryTag = sourceTag{Source: "query", Name: defaultName, Encoding: ""}
		}

		// Determine field size limit.
		// Default is 16KB, overridden by maxLength tag.
		limit, err := fieldLengthLimit(sf)
		if err != nil {
			return newEndpointError(http.StatusInternalServerError, "", fmt.Errorf("endpoint: decode: field %s: %w", sf.Name, err))
		}

		// If a struct(-like) field can unmarshal itself from text, treat it as a leaf
		// value (e.g. time.Time) rather than recursing into its internal fields.
		//
		// Mirror setFieldFromBytes() behavior: prefer pointer receiver.
		textUnmarshalerType := reflect.TypeFor[encoding.TextUnmarshaler]()
		implementsTextUnmarshaler := false
		if fv.IsValid() {
			if fv.Kind() == reflect.Pointer {
				if fv.Type().Implements(textUnmarshalerType) {
					implementsTextUnmarshaler = true
				}
			} else {
				if fv.CanAddr() && fv.Addr().Type().Implements(textUnmarshalerType) {
					implementsTextUnmarshaler = true
				} else if fv.Type().Implements(textUnmarshalerType) {
					implementsTextUnmarshaler = true
				}
			}
		}

		// Recurse into nested structs.
		// Support both anonymous embedded structs and named struct fields.
		//
		// Only recurse when there are no tags on this field. If the field
		// has *any* tags, it should be treated as a leaf value and decoded according
		// to its tags (including `body` for struct-typed values).
		fv2 := fv
		if fv2.Kind() == reflect.Pointer {
			if fv2.IsNil() {
				// Allocate pointer-to-struct so nested fields can be set.
				if fv2.Type().Elem().Kind() == reflect.Struct {
					fv2.Set(reflect.New(fv2.Type().Elem()))
				}
			}
			if !fv2.IsNil() {
				fv2 = fv2.Elem()
			}
		}
		if fv2.IsValid() && fv2.Kind() == reflect.Struct {
			// If the field is a struct and has no tags, and
			// doeesn't implement TextUnmarshaler, recurse.
			if !hasAnyTag && !implementsTextUnmarshaler {
				if err := unmarshalStruct(r, fv2, query, form, files); err != nil {
					return err
				}
				continue
			}
		}

		pathTag.MaxLength = limit
		queryTag.MaxLength = limit
		bodyTag.MaxLength = limit
		cookieTag.MaxLength = limit
		formTag.MaxLength = limit
		headerTag.MaxLength = limit

		// Body default: for non-string/[]byte fields, default to JSON decoding.
		if hasBody && strings.TrimSpace(bodyTag.Name) != "-" && strings.TrimSpace(bodyTag.Encoding) == "" {
			ft := fv.Type()
			if fv.Kind() == reflect.Pointer {
				ft = fv.Type().Elem()
			}
			isStringOrBytes := ft.Kind() == reflect.String || (ft.Kind() == reflect.Slice && ft.Elem().Kind() == reflect.Uint8)
			if !isStringOrBytes {
				bodyTag.Encoding = "json"
			}
		}

		if hasPath {
			ok, err := setFieldFromSource(fv, pathTag, func(name string) ([][]byte, bool, error) {
				v := r.PathValue(name)
				if v == "" {
					return nil, false, nil
				}
				return [][]byte{[]byte(v)}, true, nil
			}, sf.Name)
			if err != nil {
				return err
			}
			if ok {
				continue
			}
		}
		if hasQuery {
			ok, err := setFieldFromSource(fv, queryTag, func(name string) ([][]byte, bool, error) {
				vs, present := query[name]
				if !present || len(vs) == 0 {
					return nil, false, nil
				}
				out := make([][]byte, len(vs))
				for i, s := range vs {
					out[i] = []byte(s)
				}
				return out, true, nil
			}, sf.Name)
			if err != nil {
				return err
			}
			if ok {
				continue
			}
		}
		if hasForm {
			// Special-case multipart file uploads: []*multipart.FileHeader
			//
			// If the field is tagged as a form param and is of type []*multipart.FileHeader,
			// populate it from the multipart file map rather than form text values.
			if fv.Kind() == reflect.Slice && fv.Type().Elem() == reflect.TypeOf(&multipart.FileHeader{}) {
				if files != nil {
					if hs, ok := files[formTag.Name]; ok && len(hs) > 0 {
						if !fv.CanSet() {
							return newEndpointError(http.StatusInternalServerError, "", fmt.Errorf("endpoint: decode: form %q -> %s: field is not settable", formTag.Name, sf.Name))
						}
						fv.Set(reflect.ValueOf(hs))
						continue
					}
				}
				// If no files present for this key, fall through to normal form handling.
			}

			ok, err := setFieldFromSource(fv, formTag, func(name string) ([][]byte, bool, error) {
				vs, present := form[name]
				if !present || len(vs) == 0 {
					return nil, false, nil
				}
				out := make([][]byte, len(vs))
				for i, s := range vs {
					out[i] = []byte(s)
				}
				return out, true, nil
			}, sf.Name)
			if err != nil {
				return err
			}
			if ok {
				continue
			}
		}
		if hasBody {
			ok, err := setFieldFromSource(fv, bodyTag, fetchRequestBody(r, bodyTag.Encoding), sf.Name)
			if err != nil {
				return err
			}
			if ok {
				continue
			}
		}
		if hasCookie {
			ok, err := setFieldFromSource(fv, cookieTag, fetchCookieValue(r), sf.Name)
			if err != nil {
				return err
			}
			if ok {
				continue
			}
		}
		if hasHeader {
			ok, err := setFieldFromSource(fv, headerTag, fetchHeaderValue(r), sf.Name)
			if err != nil {
				return err
			}
			if ok {
				continue
			}
		}
	}
	return nil
}

func fetchRequestBody(r *http.Request, encodingFlag string) func(name string) ([][]byte, bool, error) {
	return func(_ string) ([][]byte, bool, error) {
		if r == nil || r.Body == nil || r.Body == http.NoBody {
			return nil, false, nil
		}

		// If explicit JSON encoding is requested (or defaulted for non-string/byte types),
		// require JSON content-type.
		if encodingFlag == "json" {
			if !requestBodyIsJSON(r) {
				mt := requestBodyMediaType(r)
				if mt == "" {
					mt = "(missing)"
				}
				return nil, false, newEndpointError(http.StatusUnsupportedMediaType, "", fmt.Errorf("endpoint: decode: body: unsupported media type %s", mt))
			}
		}

		b, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, false, newEndpointError(http.StatusBadRequest, "", fmt.Errorf("endpoint: decode: body: %w", err))
		}
		return [][]byte{b}, true, nil
	}
}

func fetchCookieValue(r *http.Request) func(name string) ([][]byte, bool, error) {
	return func(name string) ([][]byte, bool, error) {
		if r == nil {
			return nil, false, nil
		}
		var out [][]byte
		for _, ck := range r.Cookies() {
			if ck.Name == name {
				out = append(out, []byte(ck.Value))
			}
		}
		if len(out) == 0 {
			return nil, false, nil
		}
		return out, true, nil
	}
}

func fetchHeaderValue(r *http.Request) func(name string) ([][]byte, bool, error) {
	return func(name string) ([][]byte, bool, error) {
		if r == nil {
			return nil, false, nil
		}
		// Headers are stored with canonical keys (e.g. "Content-Type").
		// We must canonicalize the name to find it in the map.
		// Note: we access the map directly to distinguish present-but-empty from missing.
		values := r.Header[http.CanonicalHeaderKey(name)]
		if len(values) == 0 {
			return nil, false, nil
		}
		out := make([][]byte, len(values))
		for i, s := range values {
			out[i] = []byte(s)
		}
		return out, true, nil
	}
}

type sourceTag struct {
	Source    string
	Name      string
	Encoding  string
	MaxLength int
}

func fieldLengthLimit(sf reflect.StructField) (int, error) {
	val, has := sf.Tag.Lookup("maxLength")
	if !has {
		return defaultFieldLimit, nil
	}
	val = strings.TrimSpace(val)
	if val == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return 0, newEndpointError(http.StatusInternalServerError, "", fmt.Errorf("maxLength: invalid integer %q", val))
	}
	if n < 0 {
		return 0, newEndpointError(http.StatusInternalServerError, "", fmt.Errorf("maxLength: must be >= 0"))
	}
	return n, nil
}

func parseSourceTag(sf reflect.StructField, tagKey string, defaultName string) (cfg sourceTag, has bool, err error) {
	val, has := sf.Tag.Lookup(tagKey)
	if !has {
		return sourceTag{}, false, nil
	}

	parts := strings.Split(val, ",")
	name := ""
	if len(parts) > 0 {
		name = strings.TrimSpace(parts[0])
	}
	if name == "" {
		name = defaultName
	}

	// For body tags, the name is ignored for decoding purposes, but we still parse it
	// to keep option positioning consistent with other tags.

	cfg = sourceTag{Source: tagKey, Name: name, MaxLength: defaultFieldLimit}
	for _, p := range parts[1:] {
		flag := strings.ToLower(strings.TrimSpace(p))
		switch flag {
		case "":
			continue
		case "base64", "base64url":
			if cfg.Encoding != "" {
				return sourceTag{}, false, newEndpointError(http.StatusInternalServerError, "", fmt.Errorf("multiple []byte decoding flags"))
			}
			cfg.Encoding = flag
		case "json":
			if cfg.Encoding != "" {
				return sourceTag{}, false, newEndpointError(http.StatusInternalServerError, "", fmt.Errorf("multiple encoding flags"))
			}
			cfg.Encoding = flag
		default:
			return sourceTag{}, false, newEndpointError(http.StatusInternalServerError, "", fmt.Errorf("unknown %s tag flag %q", tagKey, flag))
		}
	}
	return cfg, true, nil
}

func setFieldFromSource(field reflect.Value, tag sourceTag, fetch func(name string) ([][]byte, bool, error), fieldName string) (bool, error) {
	raw, ok, err := fetch(tag.Name)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}

	for _, val := range raw {
		if tag.MaxLength > 0 && len(val) > tag.MaxLength {
			return false, newEndpointError(http.StatusBadRequest, "", fmt.Errorf("endpoint: decode: %s %q -> %s: value exceeds max length %d", tag.Source, tag.Name, fieldName, tag.MaxLength))
		}
	}

	if err := setFieldFromValues(field, raw, tag.Encoding); err != nil {
		return false, newEndpointError(http.StatusBadRequest, "", fmt.Errorf("endpoint: decode: %s %q -> %s: %w", tag.Source, tag.Name, fieldName, err))
	}
	return true, nil
}

func setFieldFromValues(v reflect.Value, values [][]byte, encodingFlag string) error {
	if len(values) == 0 {
		return nil
	}

	// Helper to resolve pointers.
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		v = v.Elem()
	}

	// Check if target is a slice (and not []byte, unless JSON).
	// Spec: "for query params, headers, cookies... append one element to the slice for each matching value"
	// However, json encoding logic says: "decode JSON into the destination field". If the field is a slice,
	// the JSON itself might be an array, so we treat it as a scalar payload (values[0]) for json.Unmarshal.
	isByteSlice := v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.Uint8
	if v.Kind() == reflect.Slice && !isByteSlice && encodingFlag != "json" {
		// Slice field: append/set each value.
		// If there's an existing slice, clear it first, otherwise create a new one.
		slice := v
		if slice.IsNil() {
			slice = reflect.MakeSlice(v.Type(), 0, len(values))
		} else {
			slice.SetLen(0)
		}

		for _, val := range values {
			// Create a new element of the slice's element type.
			elem := reflect.New(v.Type().Elem()).Elem()
			if err := setFieldFromBytesWithEncoding(elem, val, encodingFlag); err != nil {
				return err
			}
			slice = reflect.Append(slice, elem)
		}
		v.Set(slice)
		return nil
	}

	// Scalar field (or byte slice, or json): use the first value.
	return setFieldFromBytesWithEncoding(v, values[0], encodingFlag)
}

func setFieldFromBytesWithEncoding(v reflect.Value, b []byte, encodingFlag string) error {
	if !v.IsValid() {
		return newEndpointError(http.StatusInternalServerError, "", errors.New("invalid value"))
	}
	if !v.CanSet() {
		return newEndpointError(http.StatusInternalServerError, "", errors.New("field is not settable"))
	}
	if !v.CanAddr() {
		return newEndpointError(http.StatusInternalServerError, "", errors.New("field is not addressable"))
	}
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		// Recurse, following pointer.
		return setFieldFromBytesWithEncoding(v.Elem(), b, encodingFlag)
	}

	// Special-case JSON encoding.
	if encodingFlag == "json" {
		// In case of the field being a json body, it would be more
		// efficient to decode directly from the reader, but the
		// code is easier to maintain if all sources are buffered
		// into a []byte value.
		//
		// Future optimization could convert all sources to io.Reader.
		dec := json.NewDecoder(bytes.NewReader(b))
		if err := dec.Decode(v.Addr().Interface()); err != nil {
			return err
		}
		return nil
	}

	// Special-case []byte with optional encoding.
	if v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.Uint8 {
		switch encodingFlag {
		case "":
			v.SetBytes(b)
			return nil
		case "base64":
			src := bytes.TrimSpace(b)
			out := make([]byte, base64.StdEncoding.DecodedLen(len(src)))
			n, err := base64.StdEncoding.Decode(out, src)
			if err != nil {
				return err
			}
			v.SetBytes(out[:n])
			return nil
		case "base64url":
			src := bytes.TrimSpace(b)
			out := make([]byte, base64.RawURLEncoding.DecodedLen(len(src)))
			n, err := base64.RawURLEncoding.Decode(out, src)
			if err != nil {
				return err
			}
			v.SetBytes(out[:n])
			return nil
		default:
			return newEndpointError(http.StatusInternalServerError, "", fmt.Errorf("unsupported bytes decoding %q", encodingFlag))
		}
	}

	if encodingFlag == "base64" || encodingFlag == "base64url" {
		// base64 encoding is only supported for []byte fields, which was already handled earlier.
		return newEndpointError(http.StatusInternalServerError, "", fmt.Errorf("endpoint: decode: encoding %q not supported for type %s", encodingFlag, v.Type()))
	}

	// Other cases use default encoding.
	return setFieldFromBytes(v, b)
}

func setFieldFromBytes(v reflect.Value, b []byte) error {
	// Support encoding.TextUnmarshaler for custom types.
	//
	// Note: we try pointer receiver first to match common patterns
	// (e.g. time.Time uses value methods, but many custom types use pointer).
	if v.CanAddr() {
		if u, ok := v.Addr().Interface().(encoding.TextUnmarshaler); ok {
			return u.UnmarshalText(b)
		}
	}
	if u, ok := v.Interface().(encoding.TextUnmarshaler); ok {
		return u.UnmarshalText(b)
	}

	s := string(b)

	switch v.Kind() {
	case reflect.String:
		v.SetString(s)
		return nil
	case reflect.Bool:
		bb, err := strconv.ParseBool(s)
		if err != nil {
			return err
		}
		v.SetBool(bb)
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, err := strconv.ParseInt(s, 10, v.Type().Bits())
		if err != nil {
			return err
		}
		v.SetInt(n)
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, err := strconv.ParseUint(s, 10, v.Type().Bits())
		if err != nil {
			return err
		}
		v.SetUint(n)
		return nil
	case reflect.Float32, reflect.Float64:
		f, err := strconv.ParseFloat(s, v.Type().Bits())
		if err != nil {
			return err
		}
		v.SetFloat(f)
		return nil
	}

	return newEndpointError(http.StatusInternalServerError, "", fmt.Errorf("unsupported kind %s", v.Kind()))
}
