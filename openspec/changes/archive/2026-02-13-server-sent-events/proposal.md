## Why

oneserve currently lacks support for Server-Sent Events (SSE), a standard HTTP-based mechanism for server-to-client streaming. This is needed for real-time features like live dashboards, progress notifications, and status updates.

## What Changes

- Add `SSERenderer` interface and implementation in the `endpoint` package
- Introduce `SSEvent` type with ID, Type, and Data fields
- Support context cancellation for connection management

## Capabilities

### New Capabilities
- `server-sent-events`: Core SSE support enabling servers to stream events to clients over HTTP

### Modified Capabilities
None

## Impact

- New API: `SSERenderer` interface and related types
- No breaking changes to existing APIs
- No new external dependencies
- Minimal impact - additive feature only
