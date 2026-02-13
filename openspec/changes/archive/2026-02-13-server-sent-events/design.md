## Context

oneserve needs to support Server-Sent Events (SSE) for real-time server-to-client streaming. SSE is a standard HTTP-based mechanism ideal for live dashboards, progress updates, and push notifications. The existing Renderer pattern provides a clean abstraction for responses.

## Goals / Non-Goals

**Goals:**
- Add SSE support to the endpoint package
- Use Go 1.23 iterators for event streaming
- Honor context cancellation for connection management
- Follow existing Renderer patterns in the codebase
- Provide usage examples

**Non-Goals:**
- WebSocket support (different use case, different protocol)
- Binary event data (SSE text-only by spec)
- Automatic reconnection logic (client handles this)

## Decisions

### 1. Iterator over Channel
**Decision**: Use Go 1.23 iterators (`iter.Seq[SSEvent]`) instead of channels.

**Rationale**: 
- Natural cancellation via pull semantics (consumer stops pulling → stops producing)
- No explicit close coordination needed
- Cleaner API for endpoint authors - just return an iterator

**Alternative considered**: Channels - require explicit goroutine and close coordination.

### 2. Renderer Interface vs Constructor
**Decision**: Provide both a constructor and support returning `iter.Seq[SSEvent]` directly.

**Rationale**: 
- `SSERendererFunc(events iter.Seq[SSEvent])` allows simple endpoint returns
- Maintains consistency with existing Renderer pattern
- Works with existing endpoint middleware

### 3. Event Structure
**Decision**: `SSEvent` struct with optional ID, Type, and required Data fields.

**Rationale**:
- Matches SSE spec (all three fields supported)
- ID enables client-side auto-reconnect stability
- Type enables event filtering on client

## Risks / Trade-offs

- **Risk**: Client disconnects without notice  
  **Mitigation**: Writer errors are ignored; context cancellation stops the iterator

- **Risk**: Slow clients causing resource exhaustion  
  **Mitigation**: Server can buffer (not implemented initially); context timeout recommended

- **Trade-off**: Iterator requires Go 1.23+  
  **Mitigation**:oneserve already requires Go 1.23 (from go.mod)
