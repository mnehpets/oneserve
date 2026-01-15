package endpoint

import (
	"bytes"
	"errors"
	htmltmpl "html/template"
	"io"
	"net/http"
	texttmpl "text/template"
)

// TextTemplateRenderer renders a Go text/template into the response.
// Rendering is buffered to catch template execution errors before
// committing the response.
//
// Content-Type defaults to "text/plain; charset=utf-8" unless an existing
// Content-Type header is already set.
//
// Template is required.
//
// Values is optional and is passed as the template data.
//
// Name is optional; when set, ExecuteTemplate is used.
type TextTemplateRenderer struct {
	Status   int
	Template *texttmpl.Template
	Name     string
	Values   any
}

func (tr *TextTemplateRenderer) Render(w http.ResponseWriter, r *http.Request) error {
	if tr.Template == nil {
		return errors.New("endpoint: nil text/template")
	}

	// Buffer template execution so that execution errors can be surfaced before
	// the response is committed. Otherwise, template execution can start writing
	// to the client, making it impossible to change the HTTP status code.
	var buf bytes.Buffer
	var err error
	if tr.Name != "" {
		err = tr.Template.ExecuteTemplate(&buf, tr.Name, tr.Values)
	} else {
		err = tr.Template.Execute(&buf, tr.Values)
	}
	if err != nil {
		return err
	}

	setContentType(w, "text/plain; charset=utf-8")

	status := tr.Status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)

	_, err = io.Copy(w, &buf)
	return err
}

// HTMLTemplateRenderer renders a Go html/template into the response.
// Rendering is buffered to catch template execution errors before
// committing the response.
//
// Content-Type defaults to "text/html; charset=utf-8" unless an existing
// Content-Type header is already set.
//
// Template is required.
//
// Values is optional and is passed as the template data.
//
// Name is optional; when set, ExecuteTemplate is used.
type HTMLTemplateRenderer struct {
	Status   int
	Template *htmltmpl.Template
	Name     string
	Values   any
}

func (hr *HTMLTemplateRenderer) Render(w http.ResponseWriter, r *http.Request) error {
	if hr.Template == nil {
		return errors.New("endpoint: nil html/template")
	}

	// Buffer template execution so that execution errors can be surfaced before
	// the response is committed. Otherwise, template execution can start writing
	// to the client, making it impossible to change the HTTP status code.
	var buf bytes.Buffer
	var err error
	if hr.Name != "" {
		err = hr.Template.ExecuteTemplate(&buf, hr.Name, hr.Values)
	} else {
		err = hr.Template.Execute(&buf, hr.Values)
	}
	if err != nil {
		return err
	}

	setContentType(w, "text/html; charset=utf-8")

	status := hr.Status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)

	_, err = io.Copy(w, &buf)
	return err
}
