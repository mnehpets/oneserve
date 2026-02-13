package endpoint

import (
	"bytes"
	"context"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSSEvent_WriteTo(t *testing.T) {
	msg := "message"
	id1 := "1"
	empty := ""

	tests := []struct {
		name     string
		event    SSEvent
		expected string
	}{
		{"single line", SSEvent{Data: "hello"}, "data: hello\n\n"},
		{"multiline", SSEvent{Data: "line1\nline2\nline3"}, "data: line1\ndata: line2\ndata: line3\n\n"},
		{"with type", SSEvent{Type: &msg, Data: "hello"}, "event: message\ndata: hello\n\n"},
		{"with id", SSEvent{ID: &id1, Type: &msg, Data: "hello"}, "id: 1\nevent: message\ndata: hello\n\n"},
		{"empty", SSEvent{}, "data: \n\n"},
		{"trailing newline", SSEvent{Data: "Word\n"}, "data: Word\ndata: \n\n"},
		{"multiple newlines", SSEvent{Data: "\n\n"}, "data: \ndata: \ndata: \n\n"},
		{"empty id explicit", SSEvent{ID: &empty, Type: &msg, Data: "hello"}, "id: \nevent: message\ndata: hello\n\n"},
		{"empty type explicit", SSEvent{ID: &id1, Type: &empty, Data: "hello"}, "id: 1\nevent: \ndata: hello\n\n"},
		{"nil id and type", SSEvent{Data: "hello"}, "data: hello\n\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			tt.event.WriteTo(&buf)
			if buf.String() != tt.expected {
				t.Errorf("got %q, want %q", buf.String(), tt.expected)
			}
		})
	}
}

func TestSSERenderer(t *testing.T) {
	t.Run("headers", func(t *testing.T) {
		events := func(yield func(SSEvent) bool) {
			yield(SSEvent{Data: "hello"})
		}

		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/events", nil)

		(&SSERenderer{Events: events}).Render(w, r)

		if w.Header().Get("Content-Type") != "text/event-stream" {
			t.Errorf("Content-Type: got %q, want text/event-stream", w.Header().Get("Content-Type"))
		}
		if w.Header().Get("Cache-Control") != "no-cache" {
			t.Errorf("Cache-Control: got %q, want no-cache", w.Header().Get("Cache-Control"))
		}
		if w.Header().Get("Connection") != "keep-alive" {
			t.Errorf("Connection: got %q, want keep-alive", w.Header().Get("Connection"))
		}
	})

	t.Run("iteration", func(t *testing.T) {
		events := func(yield func(SSEvent) bool) {
			yield(SSEvent{Data: "first"})
			yield(SSEvent{Data: "second"})
			yield(SSEvent{Data: "third"})
		}

		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/events", nil)

		(&SSERenderer{Events: events}).Render(w, r)

		expected := "data: first\n\ndata: second\n\ndata: third\n\n"
		if w.Body.String() != expected {
			t.Errorf("got %q, want %q", w.Body.String(), expected)
		}
	})

	t.Run("empty iterator", func(t *testing.T) {
		events := func(yield func(SSEvent) bool) {
			// yields nothing
		}

		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/events", nil)

		err := (&SSERenderer{Events: events}).Render(w, r)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if w.Body.String() != "" {
			t.Errorf("expected empty body, got %q", w.Body.String())
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		events := func(yield func(SSEvent) bool) {
			<-ctx.Done()
		}

		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/events", nil).WithContext(ctx)

		err := (&SSERenderer{Events: events}).Render(w, r)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("context timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		events := func(yield func(SSEvent) bool) {
			<-time.After(1 * time.Hour) // Simulate long-running event source
		}

		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/events", nil).WithContext(ctx)

		err := (&SSERenderer{Events: events}).Render(w, r)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestSSERendererImplementsRenderer(t *testing.T) {
	var _ Renderer = &SSERenderer{}
}

type flushRecorder struct {
	*httptest.ResponseRecorder
	flushCount int
}

func (f *flushRecorder) Flush() {
	f.flushCount++
}

func TestSSERenderer_FlushCalled(t *testing.T) {
	events := func(yield func(SSEvent) bool) {
		yield(SSEvent{Data: "first"})
		yield(SSEvent{Data: "second"})
	}

	rec := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	r := httptest.NewRequest("GET", "/events", nil)

	(&SSERenderer{Events: events}).Render(rec, r)

	if rec.flushCount != 2 {
		t.Errorf("Flush called %d times, want 2", rec.flushCount)
	}
}
