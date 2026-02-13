# server-sent-events Specification

## Purpose
Provide a Renderer implementation that streams Server-Sent Events (SSE) to HTTP clients using Go 1.23 iterators.

## Requirements

### Requirement: SSEvent type
The system MUST provide an SSEvent type that represents a Server-Sent Event with ID, Type, and Data fields.

#### Scenario: SSEvent WriteTo encodes to SSE format
- **WHEN** SSEvent.WriteTo is called with an io.Writer
- **THEN** the output MUST be valid SSE format
- **AND** the Data field MUST be encoded as one or more "data:" lines
- **AND** if Type is non-nil, an "event:" line MUST be included with the Type value (empty string means default "message")
- **AND** if ID is non-nil, an "id:" line MUST be included with the ID value (empty string resets last-event-id)

### Requirement: SSERenderer streams events
The system MUST provide an SSERenderer that implements Renderer and streams SSEvent values over HTTP.

#### Scenario: SSE response headers
- **WHEN** SSERenderer.Render is called
- **THEN** the response MUST include Content-Type "text/event-stream"
- **AND** the response MUST include Cache-Control "no-cache"
- **AND** the response MUST include Connection "keep-alive"

#### Scenario: Iterator-based event source
- **WHEN** SSERenderer is constructed with an iter.Seq[SSEvent]
- **THEN** the renderer MUST iterate over events each to the response
- **AND** the renderer MUST flush after each event

#### Scenario: Context cancellation
- **WHEN** the request context is cancelled
- **THEN** the renderer MUST stop iterating and return without error

#### Scenario: Terminal renderer
- **WHEN** SSERenderer.Render is called
- **THEN** it MUST be terminal (MUST write the response and MUST NOT call any subsequent renderer)


