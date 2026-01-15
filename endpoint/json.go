package endpoint

import (
	"encoding/json"
	"io"
	"net/http"
)

// JSONRenderer serializes a value as JSON and writes it to the response.
//
// JSONRenderer is terminal: it MUST call WriteHeader and MUST NOT call next.
//
// Content-Type is always set to "application/json".
//
// Error handling:
//   - If encoding fails, JSONRenderer returns the encoding error.
//
// Note: since writing the response may have already started, callers should
// treat returned encoding errors as best-effort signals.
//
// This renderer uses json.Encoder which appends a trailing newline.
type JSONRenderer struct {
	Status int
	Value  interface{}

	// EncoderFactory optionally customizes encoder creation.
	// When nil, json.NewEncoder is used.
	EncoderFactory func(w io.Writer) *json.Encoder
}

func (jr *JSONRenderer) Render(w http.ResponseWriter, _ *http.Request) error {
	w.Header().Set("Content-Type", "application/json")

	status := jr.Status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)

	enc := (*json.Encoder)(nil)
	if jr.EncoderFactory != nil {
		enc = jr.EncoderFactory(w)
	} else {
		enc = json.NewEncoder(w)
		enc.SetEscapeHTML(false)
	}
	if enc == nil {
		// Treat a nil factory return as a programming error.
		return io.ErrUnexpectedEOF
	}
	return enc.Encode(jr.Value)
}
