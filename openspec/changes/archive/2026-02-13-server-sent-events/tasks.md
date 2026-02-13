## 1. Core Types

- [x] 1.1 Create SSEvent struct with ID, Type, Data fields in endpoint/sse.go
- [x] 1.2 Implement SSEvent.WriteTo(io.Writer) for SSE encoding
- [x] 1.3 Handle multiline data encoding (prefix each line with "data: ")

## 2. SSERenderer

- [x] 2.1 Create SSERenderer struct with Events iter.Seq[SSEvent]
- [x] 2.2 Implement Renderer interface (Render method)
- [x] 2.3 Set proper HTTP headers (Content-Type, Cache-Control, Connection)
- [x] 2.4 Iterate events and write with flushing
- [x] 2.5 Handle context cancellation

## 3. Testing

- [x] 3.1 Write unit tests for SSEvent.WriteTo (single line, multiline, with ID/Type)
- [x] 3.2 Write unit tests for SSERenderer (headers, iteration, context cancellation)

## 4. Documentation

- [x] 4.1 Add usage example to endpoint package or example directory
- [x] 4.2 Update README.md with SSE feature if needed
