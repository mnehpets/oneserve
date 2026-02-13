package endpoint

import (
	"fmt"
	"io"
	"iter"
	"net/http"
	"strings"
)

// SSEvent represents a Server-Sent Event to be streamed to a client.
type SSEvent struct {
	ID   *string // Optional event ID for client auto-reconnect. nil = not set, "" = reset
	Type *string // Optional event type for client filtering. nil = not set, "" = default "message"
	Data string  // Required payload
}

// WriteTo implements io.WriterTo.
func (e SSEvent) WriteTo(w io.Writer) (int64, error) {
	// Use strings.Builder for efficient string concatenation
	var sb strings.Builder

	if e.ID != nil {
		sb.WriteString("id: ")
		sb.WriteString(*e.ID)
		sb.WriteString("\n")
	}
	if e.Type != nil {
		sb.WriteString("event: ")
		sb.WriteString(*e.Type)
		sb.WriteString("\n")
	}
	sb.WriteString("data: ")
	sb.WriteString(strings.ReplaceAll(e.Data, "\n", "\ndata: "))
	sb.WriteString("\n\n")

	n, err := io.WriteString(w, sb.String())
	return int64(n), err
}

// SSERenderer streams SSEvent values to an HTTP client.
//
// It implements endpoint.Renderer and uses Go 1.23 iterators for the event source.
// The renderer sets appropriate SSE headers and flushes after each event.
type SSERenderer struct {
	Events iter.Seq[SSEvent]
}

// Render streams events to the client.
func (r *SSERenderer) Render(w http.ResponseWriter, req *http.Request) error {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		return fmt.Errorf("sse: ResponseWriter does not implement http.Flusher")
	}

	ctx := req.Context()

	// Buffered channel (size 1) prevents goroutine from blocking when
	// main loop is busy writing.
	eventCh := make(chan SSEvent, 1)

	// Goroutine bridges the iterator to the channel, checking context
	// before each yield to detect cancellation and terminate the iterator.
	go func() {
		for event := range r.Events {
			select {
			case <-ctx.Done():
				return
			case eventCh <- event:
			}
		}
		close(eventCh)
	}()

	for {
		// Either handle the next event, or a cancellation.
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-eventCh:
			if !ok {
				return nil
			}
			if _, err := event.WriteTo(w); err != nil {
				return err
			}
			flusher.Flush()
		}
	}
}
